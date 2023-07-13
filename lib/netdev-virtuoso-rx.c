#include <config.h>

#include "netdev-provider.h"
#include "netdev-virtuoso-rx.h"
#include "netdev-virtuoso-rx-private.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <net/if.h>

#include <tas_memif.h>

#include "netdev.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "netdev-native-tnl.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(netdev_virtuosorx);

enum tunnel_layers {
    TNL_L2 = 1 << 0,       /* 1 if a tunnel type can carry Ethernet traffic. */
    TNL_L3 = 1 << 1        /* 1 if a tunnel type can carry L3 traffic. */
};

struct virtuosorx_class {
  const char *dpif_port;
  struct netdev_class netdev_class;
};

static int
netdev_virtuosorx_rxq_recvrx(struct netdev_virtuosorx *dev, 
    struct dp_packet_batch *batch);
static int
netdev_virtuosorx_rxq_recvtx(struct netdev_virtuosorx *dev,
    struct dp_packet_batch *batch);

bool 
netdev_virtuosorx_is_virtuosorx_class(const struct netdev_class *class)
{
  return is_virtuosorx_class(class);
}

static struct netdev *
netdev_virtuosorx_alloc(void)
{
  struct netdev_virtuosorx *netdev = xzalloc(sizeof *netdev);
  return &netdev->up;
}

static void *
map_region(const char *name, size_t len, int fd, off_t off)
{
  void *m;
  int fd_old = fd;

  if (fd == -1)
  {
    if ((fd = shm_open(name, O_RDWR, 0)) == -1) 
    {
      VLOG_ERR("map_region: shm_open memory failed");
      return NULL;
    }
  }

  m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
      fd, off);

  /* Close fd only if it wasn't passed in */
  if (fd_old == -1)
  {
    close(fd);

  }

  if (m == (void *) -1) 
  {
    VLOG_ERR("map_region: mmap failed");
    return NULL;
  }

  return m;
}

static void *
map_region_huge(const char *name, size_t len, int fd, off_t off)
{
  void *m;
  char path[128];
  int fd_old = fd;

  snprintf(path, sizeof(path), "%s/%s", FLEXNIC_HUGE_PREFIX, name);

  if (fd == -1)
  {
    if ((fd = open(path, O_RDWR)) == -1) {
      VLOG_ERR("map_region_huge: shm_open memory failed");
      return NULL;
    }
  }

  m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, off);

  /* Close fd only if it wasn't passed in */
  if (fd_old == -1)
  {
    close(fd);
  }

  if (m == (void *) -1) {
    VLOG_ERR("map_region_huge: mmap failed");
    return NULL;
  }

  return m;
}

int
netdev_virtuosorx_construct(struct netdev *netdev_)
{
  int i;
  volatile struct flexnic_info *fi;
  volatile struct flextcp_pl_mem *fs;
  struct netdev_virtuosorx *dev = netdev_virtuosorx_cast(netdev_);
  char shm_name[20];
  void *m_shm[FLEXNIC_PL_VMST_NUM + 1];
  void *m;

  ovs_mutex_init(&dev->mutex);
  /* TODO: Revisit this and figure out if we 
     want a random address or something else */
  eth_addr_random(&dev->etheraddr);

  /* return error, if already connected */
  if (dev->info != NULL) 
  {
    VLOG_ERR( "netdev_virtuosorx_construct: already mapped\n");
    return -1;
  }

  /* open and map flexnic info shm region */
  if ((m = map_region(FLEXNIC_NAME_INFO, FLEXNIC_INFO_BYTES, -1, 0)) == NULL) 
  {
    VLOG_ERR("netdev_virtuosorx_construct: map_region info failed");
    return -1;
  }

  /* abort if not ready yet */
  fi = (volatile struct flexnic_info *) m;
  if ((fi->flags & FLEXNIC_FLAG_READY) != FLEXNIC_FLAG_READY) 
  {
    goto error_unmap_info;
  }

  /* open and map flexnic internal memory shm region */
  if ((fi->flags & FLEXNIC_FLAG_HUGEPAGES) == FLEXNIC_FLAG_HUGEPAGES) 
  {
    m = map_region_huge(FLEXNIC_NAME_INTERNAL_MEM, fi->internal_mem_size,
        -1, 0);
  } else 
  {
    m = map_region(FLEXNIC_NAME_INTERNAL_MEM, fi->internal_mem_size,
        -1, 0);
  }

  if (m == NULL) 
  {
    VLOG_ERR("netdev_virtuosorx_construct: map_region internal state failed");
    goto error_unmap_info;
  }

  fs = (volatile struct flextcp_pl_mem *) m;


  /* open and map all dma shm region */
  if ((dev->shms = malloc((FLEXNIC_PL_VMST_NUM + 1) * sizeof(void *))) == NULL) 
  {
    VLOG_ERR("netdev_virtuosorx_construct: failed to malloc handles for shm");
    goto error_unmap_fp_state;
  }

  for (i = 0; i < FLEXNIC_PL_VMST_NUM + 1; i++)
  {
    snprintf(shm_name, sizeof(shm_name), "%s_vm%d", 
        FLEXNIC_NAME_DMA_MEM, i);
    if ((fi->flags & FLEXNIC_FLAG_HUGEPAGES) == FLEXNIC_FLAG_HUGEPAGES) 
    {
      m = map_region_huge(shm_name, fi->dma_mem_size, 
          -1, fi->dma_mem_off);
    } else 
    {
      m = map_region(shm_name, fi->dma_mem_size, 
          -1, fi->dma_mem_off);
    }

    if (m == NULL) 
    {
      VLOG_ERR("netdev_virtuosorx_construct: mapping dma memory failed");
      goto error_unmap_shm;
    }

    m_shm[i] = m;
    dev->shms[i] = m;
  }

  dev->info = fi;
  dev->fp_state = fs;

  return 0;

error_unmap_shm:
  for (i = i - 1; i >= 0; i--)
  {
    munmap(m_shm[i], fi->dma_mem_size);
  }
error_unmap_fp_state:
  munmap(m, fi->internal_mem_size);
error_unmap_info:
  munmap(m, FLEXNIC_INFO_BYTES);
  return -1;
}

static void
netdev_virtuosorx_destruct(struct netdev *netdev_)
{
  int i;
  struct netdev_virtuosorx *netdev = netdev_virtuosorx_cast(netdev_);

  ovs_mutex_destroy(&netdev->mutex);
  /* Unmap shared memory region for each VM and slow path */
  for (i = 0; i < FLEXNIC_PL_VMST_NUM + 1; i++)
  {
    munmap((void *) netdev->shms[i], netdev->info->dma_mem_size);
  }
  
  /* Unmap shared memory region for internal state */
  munmap((void *) netdev->fp_state, netdev->info->internal_mem_size);

  /* Unmap virtuoso info */
  munmap((void *) netdev->info, FLEXNIC_INFO_BYTES);
}

static void 
netdev_virtuosorx_dealloc(struct netdev *netdev_)
{
  struct netdev_virtuosorx *netdev = netdev_virtuosorx_cast(netdev_);
  free(netdev);
}

static int
netdev_virtuosorx_set_etheraddr(struct netdev *netdev_, 
                                const struct eth_addr mac)
{
    struct netdev_virtuosorx *netdev = netdev_virtuosorx_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->etheraddr = mac;
    ovs_mutex_unlock(&netdev->mutex);
    netdev_change_seq_changed(netdev_);

    return 0;
}

static int
netdev_virtuosorx_get_etheraddr(const struct netdev *netdev_, 
                                struct eth_addr *mac)
{
    struct netdev_virtuosorx *netdev = netdev_virtuosorx_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *mac = netdev->etheraddr;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_virtuosorx_update_flags(struct netdev *netdev OVS_UNUSED,
                               enum netdev_flags off,
                               enum netdev_flags on OVS_UNUSED,
                               enum netdev_flags *old_flagsp)
{
    if (off & (NETDEV_UP)) 
    {
        return EOPNOTSUPP;
    }

    *old_flagsp = NETDEV_UP;
    return 0;
}


/* Performs periodic work needed by Virtuoso */
static void
netdev_virtuosorx_run(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

/* Arranges for poll_block to wake up if run function needs to be called */
static void 
netdev_virtuosorx_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

static int
netdev_virtuosorx_rxq_construct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  return 0;
}

static void
netdev_virtuosorx_rxq_destruct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  return;
}

static struct netdev_rxq *
netdev_virtuosorx_rxq_alloc(void)
{
  struct netdev_rxq_virtuosorx *rx = xzalloc(sizeof *rx);
  return &rx->up;
}

static void
netdev_virtuosorx_rxq_dealloc(struct netdev_rxq *rxq_)
{
  struct netdev_rxq_virtuosorx *rx = netdev_rxq_virtuosorx_cast(rxq_);
  free(rx);
}

static int
netdev_virtuosorx_rxq_recv(struct netdev_rxq *rxq_ OVS_UNUSED, 
                           struct dp_packet_batch *batch, int *qfill OVS_UNUSED)
{
  int retrx, rettx;
  struct netdev_rxq_virtuosorx *rxq = netdev_rxq_virtuosorx_cast(rxq_);
  struct netdev *netdev_ = rxq->up.netdev;
  struct netdev_virtuosorx *netdev = netdev_virtuosorx_cast(netdev_);
  dp_packet_batch_init(batch);
 
  /* Get incoming packets from Virtuoso */
  retrx = netdev_virtuosorx_rxq_recvrx(netdev, batch);

  /* Get outgoing packets from Virtuoso */
  rettx = netdev_virtuosorx_rxq_recvtx(netdev, batch);

  if (retrx ==  EAGAIN && rettx == EAGAIN)
    return EAGAIN;

  return 0;
}

static int
netdev_virtuosorx_rxq_recvrx(struct netdev_virtuosorx *dev, 
    struct dp_packet_batch *batch)
{
  int mtu;
  uint16_t msg_len, pkt_len;
  struct dp_packet *pkt;
  volatile struct flextcp_pl_ovsctx *tasovs = &dev->fp_state->tasovs;
  volatile struct flextcp_pl_toe *toe;
  void *virtuoso_buf;
  uintptr_t addr;
  uint8_t type;

  addr = tasovs->rx_base + tasovs->rx_tail;
  msg_len = sizeof(*toe);

  ovs_assert(addr + msg_len >= addr && addr + msg_len <= dev->info->dma_mem_size);
  toe = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + addr);

  /* Kernel queue empty so do nothing */
  type = toe->type;
  if (type == FLEXTCP_PL_TOE_INVALID)
  {
    return EAGAIN;
  }

  /* Get packet from shm */
  pkt_len = toe->msg.packet.len;
  virtuoso_buf = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + toe->addr);
  
  /* Add packet to datapath batch */
  mtu = ETH_PAYLOAD_MAX;
  pkt = dp_packet_new_with_headroom(pkt_len + mtu, DP_NETDEV_HEADROOM);
  memcpy(dp_packet_data(pkt), virtuoso_buf, pkt_len);
  dp_packet_set_size(pkt, pkt_len);

  pkt->md.flow_group = toe->msg.packet.flow_group;
  pkt->md.fn_core = toe->msg.packet.fn_core;
  pkt->md.vmid = toe->msg.packet.vmid;
  pkt->md.rxpkt = true;

  tasovs->rx_tail += sizeof(*toe);
  if (tasovs->rx_tail >= tasovs->rx_len)
    tasovs->rx_tail -= tasovs->rx_len;

  toe->type = 0;
  
  dp_packet_batch_add(batch, pkt);
  return 0;
}

static int
netdev_virtuosorx_rxq_recvtx(struct netdev_virtuosorx *dev,
    struct dp_packet_batch *batch)
{
  int mtu;
  uint16_t msg_len, pkt_len;
  struct dp_packet *pkt;
  volatile struct flextcp_pl_ovsctx *tasovs = &dev->fp_state->tasovs;
  volatile struct flextcp_pl_toe *toe;
  void *virtuoso_buf;
  uintptr_t addr;
  uint8_t type;

  addr = tasovs->tx_base + tasovs->tx_tail;
  msg_len = sizeof(*toe);

  ovs_assert(addr + msg_len >= addr && addr + msg_len <= dev->info->dma_mem_size);
  toe = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + addr);

  /* Kernel queue empty so do nothing */
  type = toe->type;
  if (type == FLEXTCP_PL_TOE_INVALID)
  {
    return EAGAIN;
  }

  /* Get packet from shm */
  pkt_len = toe->msg.packet.len;
  virtuoso_buf = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + toe->addr);

  /* Add packet to datapath batch */
  mtu = ETH_PAYLOAD_MAX;
  pkt = dp_packet_new_with_headroom(pkt_len + mtu, DP_NETDEV_HEADROOM);
  memcpy(dp_packet_data(pkt), virtuoso_buf, pkt_len);
  dp_packet_set_size(pkt, pkt_len);

  pkt->md.flow_group = toe->msg.packet.flow_group;
  pkt->md.fn_core = toe->msg.packet.fn_core;
  pkt->md.vmid = toe->msg.packet.vmid;
  pkt->md.connaddr = toe->msg.packet.connaddr;
  pkt->md.rxpkt = false;

  tasovs->tx_tail += sizeof(*toe);
  if (tasovs->tx_tail >= tasovs->tx_len)
    tasovs->tx_tail -= tasovs->tx_len;

  toe->type = 0;
  
  dp_packet_batch_add(batch, pkt);
  return 0;
}

static void
netdev_virtuosorx_rxq_wait(struct netdev_rxq *rxq_ OVS_UNUSED)
{

}

static int
netdev_virtuosorx_rxq_drain(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  return 0;
}

#define NETDEV_VIRTUOSORX_COMMON_FUNCTIONS                   \
  .run = netdev_virtuosorx_run,                              \
  .wait = netdev_virtuosorx_wait,                            \
  .alloc = netdev_virtuosorx_alloc,                          \
  .construct = netdev_virtuosorx_construct,                  \
  .destruct = netdev_virtuosorx_destruct,                    \
  .dealloc = netdev_virtuosorx_dealloc,                      \
  .set_etheraddr = netdev_virtuosorx_set_etheraddr,          \
  .get_etheraddr = netdev_virtuosorx_get_etheraddr,          \
  .update_flags = netdev_virtuosorx_update_flags,            \
  .build_header = netdev_gre_build_header,                   \
  .pop_header = netdev_gre_pop_header,                       \
  .push_header = netdev_gre_push_header                     

#define NETDEV_VIRTUOSORX_RX_FUNCTIONS                       \
  .rxq_construct = netdev_virtuosorx_rxq_construct,          \
  .rxq_destruct = netdev_virtuosorx_rxq_destruct,            \
  .rxq_alloc = netdev_virtuosorx_rxq_alloc,                  \
  .rxq_dealloc = netdev_virtuosorx_rxq_dealloc,              \
  .rxq_recv = netdev_virtuosorx_rxq_recv,                    \
  .rxq_wait = netdev_virtuosorx_rxq_wait,                    \
  .rxq_drain = netdev_virtuosorx_rxq_drain            


const struct netdev_class netdev_virtuosorx_class = {
  NETDEV_VIRTUOSORX_COMMON_FUNCTIONS,
  NETDEV_VIRTUOSORX_RX_FUNCTIONS,
  .type = "virtuosorx",
  .is_pmd = true,
};