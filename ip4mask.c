/* $Id$
 */

#include "ip4addr.h"

ip4addr_t ip4mask(unsigned bits) {
  ip4addr_t mask;
  for(mask = 0; bits; --bits)
    mask = (mask >> 1) | 0x80000000u;
  return mask;
}
