/* ip4atos() converts binary IP4 address into textual printable
 * dotted-quad form.
 */

#include "ip4addr.h"

/* helper routine for ip4atos() */

static char *oct(char *s, unsigned char o, char e) {
  if (o >= 100) {
    *s++ = o / 100 + '0', o %= 100;
    *s++ = o / 10 + '0', o %= 10;
  }
  else if (o >= 10)
    *s++ = o / 10 + '0', o %= 10;
  *s++ = o + '0';
  *s++ = e;
  return s;
}

/* return printable representation of ip4addr like inet_ntoa() */

const char *ip4atos(ip4addr_t a) {
  static char buf[16];
  oct(oct(oct(oct(buf,
    (a >> 24) & 0xff, '.'),
    (a >> 16) & 0xff, '.'),
    (a >>  8) & 0xff, '.'),
    a & 0xff, '\0');
  return buf;
}
