/* $Id$
 * ip4mask(), given number of significant bits in network
 * prefix, return IP4 network mask.
 */

#include "ip4addr.h"

ip4addr_t ip4mask(unsigned bits) {
  ip4addr_t mask;
  for (mask = 0, bits = 32 - bits; bits; --bits)
    mask = (mask << 1) | 1;
  return ~mask;
}
