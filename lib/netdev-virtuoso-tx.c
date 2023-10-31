#include <config.h>

#include "netdev-provider.h"
#include "netdev-virtuoso-tx.h"
#include "netdev-virtuoso-tx-private.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <net/if.h>
#include <rte_memcpy.h>

#include <tas_memif.h>

#include "netdev.h"
#include "dp-packet.h"
#include "dpif-netdev.h"
#include "netdev-native-tnl.h"
#include "ovs-rcu.h"
#include "openvswitch/vlog.h"
#include "smap.h"
#include "socket-util.h"


VLOG_DEFINE_THIS_MODULE(netdev_virtuosotx);

enum tunnel_layers {
    TNL_L2 = 1 << 0,       /* 1 if a tunnel type can carry Ethernet traffic. */
    TNL_L3 = 1 << 1        /* 1 if a tunnel type can carry L3 traffic. */
};

struct virtuosotx_class {
  const char *dpif_port;
  struct netdev_class netdev_class;
};

static int 
netdev_virtuosotx_sendrx(struct netdev_virtuosotx *dev, struct dp_packet *pkt);
static int 
netdev_virtuosotx_sendtx(struct netdev_virtuosotx *dev, struct dp_packet *pkt);
static int 
parse_ip(const char *value, struct in_addr *ip);
static ovs_be32 
parse_key(const struct smap *args, const char *name);
int 
util_parse_ipv4(const char *s, uint32_t *ip);

int 
util_parse_ipv4(const char *s, uint32_t *ip)
{
  if (inet_pton(AF_INET, s, ip) != 1) {
    return -1;
  }
  *ip = htonl(*ip);
  return 0;
}

bool 
netdev_virtuosotx_is_virtuoso_class(const struct netdev_class *class)
{
  return is_virtuosotx_class(class);
}

static struct netdev *
netdev_virtuosotx_alloc(void)
{
  struct netdev_virtuosotx *netdev = xzalloc(sizeof *netdev);
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
netdev_virtuosotx_construct(struct netdev *netdev_)
{
  int i;
  volatile struct flexnic_info *fi;
  volatile struct flextcp_pl_mem *fs;
  struct netdev_virtuosotx *dev = netdev_virtuosotx_cast(netdev_);
  char shm_name[20];
  void *m_shm[FLEXNIC_PL_VMST_NUM + 1];
  void *m;

  ovs_mutex_init(&dev->mutex);
  ovs_mutex_init(&dev->tx_mutex);
  /* TODO: Revisit this and figure out if we 
     want a random address or something else */
  eth_addr_random(&dev->etheraddr);

  /* return error, if already connected */
  if (dev->info != NULL) 
  {
    VLOG_ERR( "netdev_virtuosotx_construct: already mapped\n");
    return -1;
  }

  /* open and map flexnic info shm region */
  if ((m = map_region(FLEXNIC_NAME_INFO, FLEXNIC_INFO_BYTES, -1, 0)) == NULL) 
  {
    VLOG_ERR("netdev_virtuosotx_construct: map_region info failed");
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
    VLOG_ERR("netdev_virtuosotx_construct: map_region internal state failed");
    goto error_unmap_info;
  }

  fs = (volatile struct flextcp_pl_mem *) m;


  /* open and map all dma shm region */
  if ((dev->shms = malloc((FLEXNIC_PL_VMST_NUM + 1) * sizeof(void *))) == NULL) 
  {
    VLOG_ERR("netdev_virtuosotx_construct: failed to malloc handles for shm");
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
      VLOG_ERR("netdev_virtuosotx_construct: mapping dma memory failed");
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
netdev_virtuosotx_destruct(struct netdev *netdev_)
{
  int i;
  struct netdev_virtuosotx *netdev = netdev_virtuosotx_cast(netdev_);

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
netdev_virtuosotx_dealloc(struct netdev *netdev_)
{
  struct netdev_virtuosotx *netdev = netdev_virtuosotx_cast(netdev_);
  free(netdev);
}

static int
netdev_virtuosotx_set_etheraddr(struct netdev *netdev_, 
                              const struct eth_addr mac)
{
    struct netdev_virtuosotx *netdev = netdev_virtuosotx_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    netdev->etheraddr = mac;
    ovs_mutex_unlock(&netdev->mutex);
    netdev_change_seq_changed(netdev_);

    return 0;
}

static int
netdev_virtuosotx_get_etheraddr(const struct netdev *netdev_, 
                              struct eth_addr *mac)
{
    struct netdev_virtuosotx *netdev = netdev_virtuosotx_cast(netdev_);

    ovs_mutex_lock(&netdev->mutex);
    *mac = netdev->etheraddr;
    ovs_mutex_unlock(&netdev->mutex);

    return 0;
}

static int
netdev_virtuosotx_update_flags(struct netdev *netdev OVS_UNUSED,
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

static int 
netdev_virtuosotx_set_config(struct netdev *dev_, const struct smap *args, char **errp)
{
  struct netdev_virtuosotx *dev = netdev_virtuosotx_cast(dev_);
  const char *name = netdev_get_name(dev_);
  const char *type = netdev_get_type(dev_);
  struct ds errors = DS_EMPTY_INITIALIZER;
  struct smap_node *node;
  int err = 0;

  SMAP_FOR_EACH (node, args)
  {
    if (!strcmp(node->key, "out_remote_ip"))
    {
      err = parse_ip(node->value, &dev->out_remote_ip);
      switch (err) 
      {
      case ENOENT:
        ds_put_format(&errors, "%s: bad %s 'out_remote_ip'\n", name, type);
        break;
      case EINVAL:
        ds_put_format(&errors,
                      "%s: multicast out_remote_ip=%s not allowed\n",
                      name, node->value);
        goto out;
      }
    } else if (!strcmp(node->key, "out_local_ip"))
    {
      err = parse_ip(node->value, &dev->out_local_ip);
      switch (err) 
      {
      case ENOENT:
        ds_put_format(&errors, "%s: bad %s 'out_local_ip'\n", name, type);
        break;
      case EINVAL:
        ds_put_format(&errors,
                      "%s: multicast out_local_ip=%s not allowed\n",
                      name, node->value);
        goto out;
      }
    } else if (!strcmp(node->key, "in_remote_ip"))
    {
      err = parse_ip(node->value, &dev->in_remote_ip);
      switch (err) 
      {
      case ENOENT:
        ds_put_format(&errors, "%s: bad %s 'in_remote_ip'\n", name, type);
        break;
      case EINVAL:
        ds_put_format(&errors,
                      "%s: multicast in_remote_ip=%s not allowed\n",
                      name, node->value);
        goto out;
      }
    } else if (!strcmp(node->key, "in_local_ip"))
    {
      err = parse_ip(node->value, &dev->in_local_ip);
      switch (err) 
      {
      case ENOENT:
        ds_put_format(&errors, "%s: bad %s 'in_local_ip'\n", name, type);
        break;
      case EINVAL:
        ds_put_format(&errors,
                      "%s: multicast in_local_ip=%s not allowed\n",
                      name, node->value);
        goto out;
      }
    }
  }

  dev->gre_key = parse_key(args, "key");

  if (dev->gre_key == 0)
    goto out;

  return 0;

out:
    if (errors.length) {
        ds_chomp(&errors, '\n');
        VLOG_WARN("%s", ds_cstr(&errors));
        if (err) {
            *errp = ds_steal_cstr(&errors);
        }
    }

    ds_destroy(&errors);

    return err;
}

static int
netdev_virtuosotx_get_config(const struct netdev *dev_ OVS_UNUSED, 
    struct smap *args OVS_UNUSED)
{
  return 0;
}

/* Performs periodic work needed by Virtuoso */
static void
netdev_virtuosotx_run(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

/* Arranges for poll_block to wake up if run function needs to be called */
static void 
netdev_virtuosotx_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{

}

static int
netdev_virtuosotx_send(struct netdev *netdev_, int qid OVS_UNUSED,
                       struct dp_packet_batch *batch OVS_UNUSED,
                       bool concurrent_txq OVS_UNUSED)
{
  int ret = 0;
  int packet_drops = 0;
  struct netdev_virtuosotx *netdev = netdev_virtuosotx_cast(netdev_);
  struct dp_packet *pkt;


  ovs_mutex_lock(&netdev->tx_mutex);
  DP_PACKET_BATCH_FOR_EACH(i, pkt, batch)
  {
    if (pkt->md.rxpkt && pkt->md.in_port.ofp_port != 0)
    {
      ret = netdev_virtuosotx_sendrx(netdev, pkt);
    } else if (pkt->md.in_port.ofp_port != 0)
    {
      ret = netdev_virtuosotx_sendtx(netdev, pkt);
    }

    if (ret < 0)
      packet_drops++;
  }
  ovs_mutex_unlock(&netdev->tx_mutex);

  if (packet_drops > 0)
  {
    return packet_drops;
  }

  return 0;
}

static int
netdev_virtuosotx_sendrx(struct netdev_virtuosotx *dev, struct dp_packet *pkt)
{
  volatile struct flextcp_pl_ovsctx *ovstas = &dev->fp_state->ovstas;
  volatile struct flextcp_pl_ote *ote;
  uintptr_t addr;
  void *buf_addr;
  uint16_t msg_len, pkt_len;

  addr = ovstas->rx_base + ovstas->rx_head;
  msg_len = sizeof(*ote);

  ovs_assert(addr + msg_len >= addr && addr + msg_len <= dev->info->dma_mem_size);
  ote = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + addr);

  if (ote->type != 0)
    return -1;

  ovstas->rx_head += sizeof(*ote);
  if (ovstas->rx_head >= ovstas->rx_len)
    ovstas->rx_head -= ovstas->rx_len;

  pkt_len = dp_packet_size(pkt);
  buf_addr = (uint8_t *) dev->shms[SP_MEM_ID] + ote->addr;
  rte_memcpy(buf_addr, dp_packet_data(pkt), pkt_len);

  ote->msg.packet.len = pkt_len;
  ote->msg.packet.flow_group = pkt->md.flow_group;
  ote->msg.packet.fn_core = pkt->md.fn_core;
  ote->key = ntohl(dev->gre_key);
  ote->out_remote_ip = ntohl(dev->out_remote_ip.s_addr);
  ote->out_local_ip = ntohl(dev->out_local_ip.s_addr);
  ote->in_remote_ip = ntohl(dev->in_remote_ip.s_addr);
  ote->in_local_ip = ntohl(dev->in_local_ip.s_addr);
  MEM_BARRIER();

  ote->type = FLEXTCP_PL_OTE_VALID;

  return 0;
}

static int
netdev_virtuosotx_sendtx(struct netdev_virtuosotx *dev, struct dp_packet *pkt)
{
  volatile struct flextcp_pl_ovsctx *ovstas = &dev->fp_state->ovstas;
  volatile struct flextcp_pl_ote *ote;
  uintptr_t addr;
  void *buf_addr;
  uint16_t msg_len, pkt_len;

  addr = ovstas->tx_base + ovstas->tx_head;
  msg_len = sizeof(*ote);

  ovs_assert(addr + msg_len >= addr && addr + msg_len <= dev->info->dma_mem_size);
  ote = (void *) ((uint8_t *) dev->shms[SP_MEM_ID] + addr);

  if (ote->type != 0) 
    return -1;

  ovstas->tx_head += sizeof(*ote);
  if (ovstas->tx_head >= ovstas->tx_len)
    ovstas->tx_head -= ovstas->tx_len;

  pkt_len = dp_packet_size(pkt);
  buf_addr = (uint8_t *) dev->shms[SP_MEM_ID] + ote->addr;
  rte_memcpy(buf_addr, dp_packet_data(pkt), pkt_len);

  ote->msg.packet.len = pkt_len;
  ote->msg.packet.flow_group = pkt->md.flow_group;
  ote->msg.packet.fn_core = pkt->md.fn_core;
  ote->msg.packet.connaddr = pkt->md.connaddr;
  ote->key = ntohl(dev->gre_key);
  ote->out_remote_ip = ntohl(dev->out_remote_ip.s_addr);
  ote->out_local_ip = ntohl(dev->out_local_ip.s_addr);
  ote->in_remote_ip = ntohl(dev->in_remote_ip.s_addr);
  ote->in_local_ip = ntohl(dev->in_local_ip.s_addr);
  MEM_BARRIER();

  ote->type = FLEXTCP_PL_OTE_VALID;

  return 0;
}

static int
parse_ip(const char *value, struct in_addr *ip)
{

  if (lookup_ip(value, ip))
  {
    return ENOENT;
  }

  return 0;
}

static ovs_be32
parse_key(const struct smap *args, const char *name)
{
  const char *s;
  s = smap_get(args, name);
  if (!s)
  {
    s = smap_get(args, "key");
    if (!s)
    {
      return 0;
    }
  }

  return htonl(strtoul(s, NULL, 0));
}

static void
netdev_virtuosotx_send_wait(struct netdev *netdev OVS_UNUSED, int qid OVS_UNUSED)
{
  
}

#define NETDEV_VIRTUOSO_COMMON_FUNCTIONS                     \
  .run = netdev_virtuosotx_run,                              \
  .wait = netdev_virtuosotx_wait,                            \
  .alloc = netdev_virtuosotx_alloc,                          \
  .construct = netdev_virtuosotx_construct,                  \
  .destruct = netdev_virtuosotx_destruct,                    \
  .dealloc = netdev_virtuosotx_dealloc,                      \
  .set_etheraddr = netdev_virtuosotx_set_etheraddr,          \
  .get_etheraddr = netdev_virtuosotx_get_etheraddr,          \
  .update_flags = netdev_virtuosotx_update_flags,            \
  .set_config = netdev_virtuosotx_set_config,                \
  .get_config = netdev_virtuosotx_get_config,                \
  .build_header = netdev_gre_build_header,                   \
  .pop_header = netdev_gre_pop_header,                       \
  .push_header = netdev_gre_push_header                      

#define NETDEV_VIRTUOSO_SEND_FUNCTIONS                       \
  .send = netdev_virtuosotx_send,                            \
  .send_wait = netdev_virtuosotx_send_wait                  


const struct netdev_class netdev_virtuosotx_class = {
  NETDEV_VIRTUOSO_COMMON_FUNCTIONS,
  NETDEV_VIRTUOSO_SEND_FUNCTIONS,
  .type = "virtuosotx",
  .is_pmd = true,
};