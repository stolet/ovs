#ifndef NETDEV_VIRTUOSO_PRIVATE_H
#define NETDEV_VIRTUOSO_PRIVATE_H 1

#include <stdbool.h>
#include <netinet/in.h>

#include "netdev-provider.h"
#include "netdev.h"

#define RX_BATCH_SIZE 6
#define TX_BATCH_SIZE 6

struct netdev_virtuosotx {
  struct netdev up;

  struct ovs_mutex tx_mutex;
  uint32_t tx_head;

  /* Protects all members below. */
  struct ovs_mutex mutex;
  volatile void **shms;
  volatile struct flexnic_info *info;
  volatile struct flextcp_pl_mem *fp_state;
  struct eth_addr etheraddr;
  struct netdev_stats stats;
  uint16_t vmid;
  ovs_be32 gre_key;
  struct in_addr out_remote_ip;
  struct in_addr out_local_ip;
  struct in_addr in_remote_ip;
  struct in_addr in_local_ip;
};

int netdev_virtuosotx_construct(struct netdev *);

static bool 
is_virtuosotx_class(const struct netdev_class *class)
{
  return class->construct == netdev_virtuosotx_construct;
}

static inline struct netdev_virtuosotx *
netdev_virtuosotx_cast(const struct netdev *netdev)
{
  ovs_assert(is_virtuosotx_class(netdev_get_class(netdev)));
  return CONTAINER_OF(netdev, struct netdev_virtuosotx, up);
}

#endif