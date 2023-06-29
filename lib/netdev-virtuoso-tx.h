#ifndef NETDEV_VIRTUOSO_H
#define NETDEV_VIRTUOSO_H 1

#include <stdbool.h>

struct netdev;
struct netdev_class;

bool netdev_virtuosotx_is_virtuoso_class(const struct netdev_class *);
const char *netdev_virtuosotx_class_get_dpif_port(const struct netdev_class *);

#endif /* netdev-virtuoso=tx.h */