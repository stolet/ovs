#ifndef NETDEV_VIRTUOSO_PRIVATE_H
#define NETDEV_VIRTUOSO_PRIVATE_H 1

#include <stdbool.h>

#include "netdev-provider.h"
#include "netdev.h"

struct netdev_virtuoso {
  struct netdev up;

  /* Protects all members below. */
  struct ovs_mutex mutex;

  struct eth_addr etheraddr;
  struct netdev_stats stats;
};

struct netdev_rxq_virtuoso {
  struct netdev_rxq up;
  uint32_t rx_tail;
  int fd;
};

int netdev_virtuoso_construct(struct netdev *);

static bool 
is_virtuoso_class(const struct netdev_class *class)
{
  return class->construct == netdev_virtuoso_construct;
}

static inline struct netdev_virtuoso *
netdev_virtuoso_cast(const struct netdev *netdev)
{
  ovs_assert(is_virtuoso_class(netdev_get_class(netdev)));
  return CONTAINER_OF(netdev, struct netdev_virtuoso, up);
}

static struct netdev_rxq_virtuoso *
netdev_rxq_virtuoso_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_virtuoso_class(netdev_get_class(rx->netdev)));

    return CONTAINER_OF(rx, struct netdev_rxq_virtuoso, up);
}

#endif