/* $Id$
 */

#include <string.h>
#include "dns.h"

/* reverse labels of the dn, return dns_dnlen() */

unsigned dns_dnreverse(const unsigned char *dn, unsigned char *rdn) {
  unsigned len = dns_dnlen(dn);
  unsigned c;

  /* start from the very end */
  rdn += len;
  *--rdn = '\0'; /* and null-terminate the dn */

  while((c = *dn) != 0) { /* process each label */
    ++c; /* include length byte */
    rdn -= c; /* this is where this label will be in rdn - back it's len */
    memcpy(rdn, dn, c);
    dn += c;
  }
  return len;
}
