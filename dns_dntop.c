/* dns_dntop() produces printable ascii representation (external form)
 * of a domain name
 */

#include "dns.h"

unsigned dns_dntop(const unsigned char *dn, char *dst, unsigned dstsiz) {
  char *d = dst;
  char *m = dst + dstsiz - 1;
  unsigned n;
  unsigned char c;

  if (!(n = *dn++)) {
    if (dstsiz < 2)
      return 0;
    *d++ = '.';
    *d++ = '\0';
    return 1;
  }
  do {
    if (d >= m)
      return 0;
    if (dst != d) *d++ = '.';
    do {
      switch((c = *dn++)) {
      case '"':
      case '.':
      case ';':
      case '\\':
      /* Special modifiers in zone files. */
      case '@':
      case '$':
        if (d + 1 >= m)
          return 0;
        *d++ = '\\';
        *d++ = c;
        break;
      default:
        if (c <= 0x20 || c >= 0x7f) {
          if (d + 3 >= m)
            return 0;
          *d++ = '\\';
          *d++ = '0' + (c / 100);
          *d++ = '0' + ((c % 100) / 10);
          *d++ = '0' + (c % 10);
        }
        else {
          if (d >= m)
            return 0;
          *d++ = c;
        }
      }
    } while(--n);
  } while((n = *dn++) != 0);
  *d = '\0';
  return d - dst;
}
