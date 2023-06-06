#include <config.h>

#include "netdev-virtuoso.h"

#include <sys/types.h>

#include "netdev.h"

VLOG_DEFINE_THIS_MODULE(netdev_virtuoso);

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

const char * 
netdev_virtuoso_class_get_dpif_port(const struct netdev_class *class)
{
  return is_virtuoso_class(class) ? virtuoso_class_cast(class)->dpif_port : NULL;
}

const char * 
netdev_virtuoso_get_dpif_port(const struct netdev *netdev.
                              char namebuf[], size_t bufsize)
{
  const struct netdev_class *class = netdev_get_class(netdev);
  const char *dpif_port = netdev_virtuoso_class_get_dpif_port(class);

  if (!dpif_port)
  {
    return netdev_get_name(netdev);
  }

  return dpif_port;
}

static struct netdev *
netdev_virtuoso_alloc(void)
{
  struct netdev_virtuoso *netdev = xzalloc(sizeof *netdev);
  return &netdev->up;
}

int
netdev_virtuoso_construct(struct netdev *netdev_)
{
  const struct netdev_class *class = netdev_get_class(netdev_);
  const char *dpif_port = netdev_virtuoso_class_get_dpif_port(class);
  struct netdev_virtuoso *dev = netdev_virtuoso_cast(netdev_);
  const char *p, *name = netdev_get_name(netdev_);
  const char *type = netdev_get_type(netdev_);
  uint16_t port = 0;

  ovs_mutex_init(&dev->mutex);
  /* TODO: Revisit this and figure out if we 
     want a random address or something else */
  eth_addr_random(&dev->etheraddr);

  if (name && dpif_port && (strlen(name) > strlen(dpif_port) + 1) &&
    (!strncmp(name, dpif_port, strlen(dpif_port)))) 
  {
    p = name + strlen(dpif_port) + 1;
    port = atoi(p);
  }

  return 0;
}

static void
netdev_virtuoso_destruct(struct netdev *netdev_)
{
  struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);
  const char *type = netdev_get_type(netdev_);

  free(netdev->peer);
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
netdev_vport_update_flags(struct netdev *netdev OVS_UNUSED,
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
  return;
}

/* Arranges for poll_block to wake up if run function needs to be called */
static void 
netdev_virtuoso_wait(const struct netdev_class *netdev_class OVS_UNUSED)
{
  return;
}

static int
netdev_virtuoso_get_queue(const struct netdev *netdev_,
                          unsigned int queue_id, struct smap *details)
{

}

static int
netdev_virtuoso_set_queue(struct netdev *netdev_,
                          unsigned int queue_id, const struct smap *details)
{

}

static int
netdev_virtuoso_delete_queue(struct netdev *netdev_, unsigned int queue_id)
{

}

static int
netdev_virtuoso_send(struct netdev *netdev_, int qid OVS_UNUSED,
                     struct dp_packet_batch *batch,
                     bool concurrent_txq OVS_UNUSED)
{

}

void
netdev_virtuoso_send_wait(struct netdev *netdev, int qid OVS_UNUSED)
{

}

static struct netdev_rxq *
netdev_virtuoso_rxq_alloc(void)
{

}

static void
netdev_virtuoso_rxq_dealloc(struct netdev_rxq *rxq_)
{

}

static int
netdev_virtuoso_rxq_recv(struct netdev_rxq *rxq_, 
                         struct dp_packet_batch *batch, int *qfill)
{

}

static void
netdev_virtuoso_rxq_wait(struct netdev_rxq *rxq_)
{

}

static int
netdev_virtuoso_rxq_drain(struct netdev_rxq *rxq_)
{

}

#define NETDEV_VIRTUOSO_CLASS_COMMON
  .run = netdev_virtuoso_run                         \
  .wait = netdev_virtuoso_wait                       \
  .alloc = netdev_virtuoso_alloc,                    \
  .construct = netdev_virtuoso_construct,            \
  .destruct = netdev_virtuoso_destruct,              \
  .dealloc = netdev_virtuoso_dealloc,                \
  .set_etheraddr = netdev_virtuoso_set_etheraddr,    \
  .get_etheraddr = netdev_virtuoso_get_etheraddr,    \
  .get_stats = netdev_virtuoso_get_stats,            \
  .update_flags = netdev_virtuoso_get_flags,         \

const struct netdev_class netdev_virtuoso_class = {
  NETDEV_VIRTUOSO_CLASS_COMMON,
  .type = "virtuoso"
};