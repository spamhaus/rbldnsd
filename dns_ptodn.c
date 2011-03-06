/* dns_ptodn() parses external textual dot-separated format
 * into a domain name
 */

#include "dns.h"
#include <errno.h>

unsigned dns_ptodn(const char *name, unsigned char *dn, unsigned dnsiz) {
  unsigned char *d;	/* current position in dn (len byte first) */
  unsigned char *label;	/* start of last label */
  unsigned char *m;	/* max byte can be filled up */
  unsigned l;		/* length of current label */
  unsigned c;		/* next input character */

  d = dn + 1;
  label = d;
  m = dn + (dnsiz > DNS_MAXDN ? DNS_MAXDN : dnsiz) - 1;

  while((c = (unsigned char)*name++) != 0) {
    if (c == '.') {
      if ((l = d - label) != 0) { /* if there was a non-empty label */
        if (l > DNS_MAXLABEL) {
          errno = EMSGSIZE;
          return 0;
        }
        label[-1] = (char)l; /* update len of last label */
        label = ++d; /* start new label, label[-1] will be len of it */
      }
      continue;
    }
    if (c == '\\') { /* handle escapes */
      if (!(c = (unsigned char)*name++))
        break;
      if (c >= '0' && c <= '9') { /* dec number: will be in c */
        c -= '0';
        if (*name >= '0' && *name <= '9') { /* 2digits */
          c = (c * 10) + (*name++ - '0');
          if (*name >= '0' && *name <= '9') { /* 3digits */
            c = (c * 10) + (*name++ - '0');
            if (c > 255) {
              errno = EINVAL;
              return 0;
            }
          }
        }
      }
    }
    if (d >= m) { /* too long? */
      errno = EMSGSIZE;
      return 0;
    }
    *d++ = (char)c; /* place next out byte */
  }

  if ((l = d - label) > DNS_MAXLABEL) {
    errno = EMSGSIZE;
    return 0;
  }
  if ((label[-1] = (char)l) != 0)
    *d++ = 0;
  return d - dn;
}
