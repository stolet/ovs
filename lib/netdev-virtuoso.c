#include <config.h>

#include "netdev-provider.h"
#include "netdev-virtuoso.h"
#include "netdev-virtuoso-private.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <tas_memif.h>

#include "netdev.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(netdev_virtuoso);

volatile void **shms = NULL;
volatile struct flexnic_info *info;
volatile struct flextcp_pl_mem *fp_state;

struct virtuoso_class {
  const char *dpif_port;
  struct netdev_class netdev_class;
};

bool 
netdev_virtuoso_is_virtuoso_class(const struct netdev_class *class)
{
  return is_virtuoso_class(class);
}

static struct virtuoso_class *
virtuoso_class_cast(const struct netdev_class *class)
{
  ovs_assert(is_virtuoso_class(class));
  return CONTAINER_OF(class, struct virtuoso_class, netdev_class);
}

static struct netdev *
netdev_virtuoso_alloc(void)
{
  struct netdev_virtuoso *netdev = xzalloc(sizeof *netdev);
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
netdev_virtuoso_construct(struct netdev *netdev_)
{
  int i;
  volatile struct flexnic_info *fi;
  volatile struct flextcp_pl_mem *fs;
  struct netdev_virtuoso *dev = netdev_virtuoso_cast(netdev_);
  char shm_name[20];
  void *m_shm[FLEXNIC_PL_VMST_NUM + 1];
  void *m;

  ovs_mutex_init(&dev->mutex);
  /* TODO: Revisit this and figure out if we 
     want a random address or something else */
  eth_addr_random(&dev->etheraddr);

  /* return error, if already connected */
  if (info != NULL) 
  {
    VLOG_ERR( "netdev_virtuoso_construct: already mapped\n");
    return -1;
  }

  /* open and map flexnic info shm region */
  if ((m = map_region(FLEXNIC_NAME_INFO, FLEXNIC_INFO_BYTES, -1, 0)) == NULL) 
  {
    VLOG_ERR("netdev_virtuoso_construct: map_region info failed");
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
    VLOG_ERR("netdev_virtuoso_construct: map_region internal state failed");
    goto error_unmap_info;
  }

  fs = (volatile struct flextcp_pl_mem *) m;


  /* open and map all dma shm region */
  if ((shms = malloc((FLEXNIC_PL_VMST_NUM + 1) * sizeof(void *))) == NULL) 
  {
    VLOG_ERR("netdev_virtuoso_construct: failed to malloc handles for shm");
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
      VLOG_ERR("netdev_virtuoso_construct: mapping dma memory failed");
      goto error_unmap_shm;
    }

    m_shm[i] = m;
    shms[i] = m;
  }

  info = fi;
  fp_state = fs;

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
netdev_virtuoso_destruct(struct netdev *netdev_)
{
  struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);

  ovs_mutex_destroy(&netdev->mutex);
}

static void 
netdev_virtuoso_dealloc(struct netdev *netdev_)
{
  struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);
  free(netdev);
}

static int
netdev_virtuoso_set_etheraddr(struct netdev *netdev_, 
                              const struct eth_addr mac)
{
    struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->etheraddr = mac;
    ovs_mutex_unlock(&netdev->mutex);
    netdev_change_seq_changed(netdev_);

    return 0;
}

static int
netdev_virtuoso_get_etheraddr(const struct netdev *netdev_, 
                              struct eth_addr *mac)
{
    struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *mac = netdev->etheraddr;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_virtuoso_update_flags(struct netdev *netdev OVS_UNUSED,
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
netdev_virtuoso_run(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

/* Arranges for poll_block to wake up if run function needs to be called */
static void 
netdev_virtuoso_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

static int
netdev_virtuoso_send(struct netdev *netdev_ OVS_UNUSED, int qid OVS_UNUSED,
                     struct dp_packet_batch *batch OVS_UNUSED,
                     bool concurrent_txq OVS_UNUSED)
{
  return 0;
}

static void
netdev_virtuoso_send_wait(struct netdev *netdev OVS_UNUSED, int qid OVS_UNUSED)
{
  
}

static int
netdev_virtuoso_rxq_construct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  struct netdev_rxq_virtuoso *rx = netdev_rxq_virtuoso_cast(rxq_);

  rx->rx_tail = 0;
  return 0;
}

static void
netdev_virtuoso_rxq_destruct(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  return;
}

static struct netdev_rxq *
netdev_virtuoso_rxq_alloc(void)
{
  struct netdev_rxq_virtuoso *rx = xzalloc(sizeof *rx);
  return &rx->up;
}

static void
netdev_virtuoso_rxq_dealloc(struct netdev_rxq *rxq_)
{
  struct netdev_rxq_virtuoso *rx = netdev_rxq_virtuoso_cast(rxq_);
  free(rx);
}

static int
netdev_virtuoso_rxq_recv(struct netdev_rxq *rxq_ OVS_UNUSED, 
                         struct dp_packet_batch *batch, int *qfill OVS_UNUSED)
{
  int mtu;
  size_t len;
  struct dp_packet *ovs_buf;
  struct netdev_rxq_virtuoso *rx = netdev_rxq_virtuoso_cast(rxq_);;
  volatile struct flextcp_pl_ovsctx *ovsctx = &fp_state->ovsctx;
  volatile struct flextcp_pl_tasovs *tasovs;
  struct nic_buffer *virtuoso_buf;
  uintptr_t addr;
  uint8_t type;

  addr = ovsctx->tasovs_base + rx->rx_tail;
  len = sizeof(*tasovs);

  ovs_assert(addr + len >= addr && addr + len <= info->dma_mem_size);
  tasovs = (void *) ((uint8_t *) shms[SP_MEM_ID] + addr);

  /* Kernel queue empty so do nothing */
  type = tasovs->type;
  if (type == FLEXTCP_PL_TASOVS_INVALID)
  {
    return 0;
  }

  VLOG_INFO("Got kernel message from Virtuoso");
  /* Get packet from shm */
  len = tasovs->msg.packet.len;
  virtuoso_buf = (void *) ((uint8_t *) shms[SP_MEM_ID] 
      + tasovs->addr + rx->rx_tail);

  /* Add packet to datapath batch */
  mtu = ETH_PAYLOAD_MAX;
  dp_packet_batch_init(batch);

  ovs_buf = dp_packet_new_with_headroom(mtu, DP_NETDEV_HEADROOM);
  memcpy(dp_packet_data(ovs_buf), virtuoso_buf, len);
  dp_packet_set_size(ovs_buf, len);
  dp_packet_batch_add(batch, ovs_buf);

  tasovs->type = 0;
  
  rx->rx_tail = rx->rx_tail + 1;
  if (rx->rx_tail == info->tasovs_len)
    rx->rx_tail -= info->tasovs_len;

  return 0;
}

static void
netdev_virtuoso_rxq_wait(struct netdev_rxq *rxq_ OVS_UNUSED)
{

}

static int
netdev_virtuoso_rxq_drain(struct netdev_rxq *rxq_ OVS_UNUSED)
{
  return 0;
}

#define NETDEV_VIRTUOSO_COMMON_FUNCTIONS             \
  .run = netdev_virtuoso_run,                        \
  .wait = netdev_virtuoso_wait,                      \
  .alloc = netdev_virtuoso_alloc,                    \
  .construct = netdev_virtuoso_construct,            \
  .destruct = netdev_virtuoso_destruct,              \
  .dealloc = netdev_virtuoso_dealloc,                \
  .set_etheraddr = netdev_virtuoso_set_etheraddr,    \
  .get_etheraddr = netdev_virtuoso_get_etheraddr,    \
  .update_flags = netdev_virtuoso_update_flags          

#define NETDEV_VIRTUOSO_SEND_FUNCTIONS               \
  .send = netdev_virtuoso_send,                      \
  .send_wait = netdev_virtuoso_send_wait            

#define NETDEV_VIRTUOSO_RX_FUNCTIONS                 \
  .rxq_construct = netdev_virtuoso_rxq_construct,    \
  .rxq_destruct = netdev_virtuoso_rxq_destruct,      \
  .rxq_alloc = netdev_virtuoso_rxq_alloc,            \
  .rxq_dealloc = netdev_virtuoso_rxq_dealloc,        \
  .rxq_recv = netdev_virtuoso_rxq_recv,              \
  .rxq_wait = netdev_virtuoso_rxq_wait,              \
  .rxq_drain = netdev_virtuoso_rxq_drain            

const struct netdev_class netdev_virtuoso_class = {
  NETDEV_VIRTUOSO_COMMON_FUNCTIONS,
  NETDEV_VIRTUOSO_SEND_FUNCTIONS,
  NETDEV_VIRTUOSO_RX_FUNCTIONS,
  .type = "virtuoso",
  .is_pmd = true
};