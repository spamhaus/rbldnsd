/* dns_dneq(): compare to domain names and return true if equal
 * (case-unsensitive)
 */

#include "dns.h"

int dns_dnequ(const unsigned char *dn1, const unsigned char *dn2) {
  unsigned c;

  for(;;) {
    if ((c = *dn1++) != *dn2++)
      return 0;
    if (!c)
      return 1;
    while(c--) {
      if (dns_dnlc(*dn1) != dns_dnlc(*dn2))
        return 0;
      ++dn1; ++dn2;
    }
  }
}
