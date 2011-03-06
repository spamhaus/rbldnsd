/* dns_dnreverse() produces reverse of a domain name
 */

#include <string.h>
#include "dns.h"

/* reverse labels of the dn, return dns_dnlen() */

unsigned
dns_dnreverse(register const unsigned char *dn,
              register unsigned char *rdn,
              register unsigned len) {
  register unsigned c;	/* length of a current label */

  if (!len)		/* if no length given, compute it */
    len = dns_dnlen(dn);

  rdn += len;		/* start from the very end */
  *--rdn = '\0';	/* and null-terminate the dn */

  while((c = *dn) != 0) {	/* process each label */
    ++c;		/* include length byte */
    rdn -= c; /* this is where this label will be in rdn - back it's len */
    memcpy(rdn, dn, c);
    dn += c;
  }

  return len;
}
