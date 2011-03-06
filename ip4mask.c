/* ip4mask(), given number of significant bits in network
 * prefix, return IP4 network mask.
 */

#include "ip4addr.h"

/* network mask for a number of bits in network part.
 * Use ~mask for host part */

const ip4addr_t ip4addr_cidr_netmasks[33] = {
  0,
  0x80000000u,0xc0000000u,0xe0000000u,0xf0000000u,
  0xf8000000u,0xfc000000u,0xfe000000u,0xff000000u,
  0xff800000u,0xffc00000u,0xffe00000u,0xfff00000u,
  0xfff80000u,0xfffc0000u,0xfffe0000u,0xffff0000u,
  0xffff8000u,0xffffc000u,0xffffe000u,0xfffff000u,
  0xfffff800u,0xfffffc00u,0xfffffe00u,0xffffff00u,
  0xffffff80u,0xffffffc0u,0xffffffe0u,0xfffffff0u,
  0xfffffff8u,0xfffffffcu,0xfffffffeu,0xffffffffu
};
