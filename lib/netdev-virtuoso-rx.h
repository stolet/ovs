#ifndef NETDEV_VIRTUOSO_H
#define NETDEV_VIRTUOSO_H 1

#include <stdbool.h>

struct netdev;
struct netdev_class;

bool netdev_virtuosorx_is_virtuosorx_class(const struct netdev_class *);
const char *netdev_virtuosorx_class_get_dpif_port(const struct netdev_class *);

#endif /* netdev-virtuoso-rx.h */