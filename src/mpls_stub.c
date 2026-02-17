#include "bgp/mpls.h"
#include <errno.h>

int nl_route_replace_v4_mpls_encap(struct in_addr pfx, uint8_t plen,
                                   struct in_addr nh,
                                   const uint32_t* labels, int label_count,
                                   int table)
{
  (void)pfx; (void)plen; (void)nh; (void)labels; (void)label_count; (void)table;
  errno = ENOSYS;
  return -1;
}

int nl_mpls_route_replace(uint32_t in_label,
                          struct in_addr nh,
                          const uint32_t* out_labels, int out_label_count)
{
  (void)in_label; (void)nh; (void)out_labels; (void)out_label_count;
  errno = ENOSYS;
  return -1;
}

int nl_mpls_route_delete(uint32_t in_label){
  (void)in_label;
  errno = ENOSYS;
  return -1;
}
