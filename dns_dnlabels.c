/* dns_dnlabels() returns number of individual labels in a domain name
 */

#include "dns.h"

unsigned dns_dnlabels(const unsigned char *dn) {
  unsigned l = 0;
  while(*dn)
    ++l, dn += 1 + *dn;
  return l;
}
