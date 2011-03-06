/* dns_dntol() lowercases a domain name
 */

#include "dns.h"

unsigned dns_dntol(const unsigned char *srcdn, unsigned char *dstdn) {
  unsigned c;
  const unsigned char *s = srcdn;
  while((c = (*dstdn++ = *s++)) != 0) {
    do {
      *dstdn++ = dns_dnlc(*s);
      ++s;
    } while(--c);
  }
  return (unsigned)(s - srcdn);
}
