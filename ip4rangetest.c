/* $Id$
 * small program to test ip4range_expand macro
 */

#include <stdio.h>
#include "ip4addr.h"
#include "rbldnsd.h"

#define octets(a) (a>>24)&255, (a>>16)&255, (a>>8)&255, a&255

int fn(unsigned idx, ip4addr_t start, unsigned count) {
  ip4addr_t step = 1u << (idx << 3);
  printf(" +%u: %u.%u.%u.%u/%u + %u.%u.%u.%u x %u\n",
    idx, octets(start), 32-(idx<<3), octets(step), count);
  return 1;
}

int main(int argc, char **argv) {
  int c;
  ip4addr_t a, b;
  for(c = 1; c < argc; ++c) {
    if (!ip4range(argv[c], &a, &b, NULL)) {
      printf("%s: parse error\n", argv[c]);
      continue;
    }
    printf(" %s: %u.%u.%u.%u-%u.%u.%u.%u\n", argv[c], octets(a), octets(b));
    ip4range_expand(a,b,fn);
  }
  return 0;
}
