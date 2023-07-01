#ifndef NETDEV_VIRTUOSO_PRIVATE_H
#define NETDEV_VIRTUOSO_PRIVATE_H 1

#include <stdbool.h>

#include "netdev-provider.h"
#include "netdev.h"

struct netdev_virtuosotx {
  struct netdev up;

  struct ovs_mutex tx_mutex;
  uint32_t tx_head;

  /* Protects all members below. */
  struct ovs_mutex mutex;
  struct eth_addr etheraddr;
  struct netdev_stats stats;
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