/* dns_dnlen(): return length of a domain name (with trailing
 * zero, as it is an integral part of DN)
 */

#include "dns.h"

unsigned dns_dnlen(register const unsigned char *dn) {
  register unsigned c;
  const unsigned char *d = dn;
  while((c = *d++) != 0)
    d += c;
  return d - dn;
}
