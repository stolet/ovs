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
    (!strncmp(name, dpif_port, strlen(dpif_port)))) {
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
virtuoso_dealloc(struct netdev *netdev_)
{
  struct netdev_virtuoso *netdev = netdev_virtuoso_cast(netdev_);
  free(netdev);
}