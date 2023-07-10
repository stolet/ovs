#ifndef NETDEV_VIRTUOSO_PRIVATE_H
#define NETDEV_VIRTUOSO_PRIVATE_H 1

#include <stdbool.h>

#include "netdev-provider.h"
#include "netdev.h"

struct netdev_virtuosorx {
  struct netdev up;

  /* Protects all members below. */
  struct ovs_mutex mutex;
  volatile void **shms;
  volatile struct flexnic_info *info;
  volatile struct flextcp_pl_mem *fp_state;
  struct eth_addr etheraddr;
  struct netdev_stats stats;
};

struct netdev_rxq_virtuosorx {
  struct netdev_rxq up;
  int fd;
};

int netdev_virtuosorx_construct(struct netdev *);

static bool 
is_virtuosorx_class(const struct netdev_class *class)
{
  return class->construct == netdev_virtuosorx_construct;
}

static inline struct netdev_virtuosorx *
netdev_virtuosorx_cast(const struct netdev *netdev)
{
  ovs_assert(is_virtuosorx_class(netdev_get_class(netdev)));
  return CONTAINER_OF(netdev, struct netdev_virtuosorx, up);
}

static struct netdev_rxq_virtuosorx *
netdev_rxq_virtuosorx_cast(const struct netdev_rxq *rx)
{
    ovs_assert(is_virtuosorx_class(netdev_get_class(rx->netdev)));

    return CONTAINER_OF(rx, struct netdev_rxq_virtuosorx, up);
}

#endif