#ifndef NETDEV_VPORT_PRIVATE_H
#define NETDEV_VPORT_PRAVITE_H 1

#include <stdbool.h>

#include "netdev.h"

struct netdev_virtuoso {
  struct netdev up;

    /* Protects all members below. */
  struct ovs_mutex mutex;

  struct eth_addr etheraddr;
  struct netdev_stats stats;
}

int 
netdev_virtuoso_construct(struct netdev *);

static bool 
is_virtuoso_class(const struct netdev_class *class)
{
  return class->construct == netdev_virtuoso_construct;
}

static inline struct netdev_virtuoso *
netdev_virtuoso_cast(const struct netdev *netdev)
{
  ovs_assert(is_virtuoso_class(netdev_get_class(netdev)));
  return CONTAINER_OF(netdev, struct netdev_vport, up);
}

#endif