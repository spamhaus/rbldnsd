/* $Id$
 * IP4 address parsing routines
 */

#include "ip4addr.h"

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((c) - '0')

#define cret(v, np, s) ((np) ? *(np) = (char*)(s), (v) : *(s) ? 0 : (v))
#define eret(np, s) ((np) ? *(np) = (char*)(s), 0 : 0)

static unsigned ip4mbits(const char *s, char **np) {
  /* helper routine for ip4cidr() and ip4range() */
  unsigned bits;
  if (!digit(*s))
    return eret(np, s - 1);
  bits = d2n(*s++);
  while(digit(*s))
    if ((bits = bits * 10 + d2n(*s++)) > 32)
      return eret(np, s - 1);
  if (!bits) return eret(np, s - 1);
  return cret(bits, np, s);
}

unsigned ip4prefix(const char *s, ip4addr_t *ap, char **np) {
  ip4addr_t o;
  *ap = 0;

#define ip4oct(bits)					\
  if (!digit(*s))					\
    return eret(np, s);					\
  o = d2n(*s++);					\
  while(digit(*s))					\
    if ((o = o * 10 + d2n(*s++)) > 255)			\
      return eret(np, s - 1);				\
  *ap |= o << bits

  ip4oct(24);
  if (*s != '.') return cret(8, np, s);
  ++s;
  ip4oct(16);
  if (*s != '.') return cret(16, np, s);
  ++s;
  ip4oct(8);
  if (*s != '.') return cret(24, np, s);
  ++s;
  ip4oct(0);
  return cret(32, np, s);

#undef ip4oct
}

/* parse ip4 CIDR range in `s', store base in *ap and
 * return number of bits */

unsigned ip4cidr(const char *s, ip4addr_t *ap, char **np) {
  unsigned bits = ip4prefix(s, ap, (char**)&s);
  if (bits && *s == '/') return ip4mbits(s + 1, np);
  return cret(bits, np, s);
}

/* parse ip4 range or CIDR in `s',
 * store start in *a1p and end in *a2p,
 * return
 *   bits if that was CIDR or prefix,
 *   32 if plain range,
 *   0 on error.
 */

unsigned ip4range(const char *s, ip4addr_t *ap, ip4addr_t *bp, char **np) {
  unsigned bits = ip4prefix(s, ap, (char**)&s);

  if (!bits) return eret(np, s);
  else if (*s == '-') {
    unsigned bbits = ip4prefix(s + 1, bp, (char**)&s);
    if (!bbits) return eret(np, s);
    if (bbits == 8) { /* treat 127.0.0.1-2 as 127.0.0.1-127.0.0.2 */
      *bp = (*bp >> (bits - 8)) | (*ap & ip4mask(bits - 8));
      bbits = bits;
    }
    if (bbits != 32) /* complete last octets */
      *bp |= ~ip4mask(bbits);
    if (*ap > *bp) return eret(np, s);
    return cret(32, np, s);
  }
  else {
    if (*s == '/') {
      bits = ip4mbits(s + 1, (char**)&s);
      if (!bits) return eret(np, s);
    }
    *bp = *ap | ~ip4mask(bits);
    return cret(bits, np, s);
  }
}

/* traditional inet_aton/inet_addr.  Werid:
 *   127.1 = 127.0.0.1
 *   1 = 0.0.0.1!!! - but here we go...
 * return #bits in _prefix_ (8,16,24 or 32), or 0 on error.
 */
unsigned ip4addr(const char *s, ip4addr_t *ap, char **np) {
  unsigned bits = ip4prefix(s, ap, np);
  switch(bits) {
    case 8: /* what a werid case! */
      *ap >>= 24;
      break;
    case 16:
      *ap = (*ap & 0xff000000u) | ((*ap >> 16) & 255);
      break;
    case 24:
      *ap = (*ap & 0xffff0000u) | ((*ap >>  8) & 255);
      break;
  }
  return bits;
}

#ifdef TEST
#include <stdio.h>

int main(int argc, char **argv) {
  int i;
  ip4addr_t a, b;
  unsigned bits;
  char *np;

#define octets(x) (x)>>24,((x)>>16)&255,((x)>>8)&255,(x)&255
#define IPFMT "%u.%u.%u.%u"

  for(i = 1; i < argc; ++i) {
    char *s = argv[i];
    printf("%s:\n", s);

    bits = ip4prefix(s, &a, NULL);
    if (!bits) printf(" pfx: err\n");
    else
      printf(" pfx: " IPFMT " bits=%u\n", octets(a), bits);
    bits = ip4prefix(s, &a, &np);
    if (!bits) printf(" pfx: err tail=`%s'\n", np);
    else
      printf(" pfx: " IPFMT " bits=%u tail=`%s'\n", octets(a), bits, np);

    bits = ip4addr(s, &a, NULL);
    if (!bits) printf(" addr: err\n");
    else printf(" addr: " IPFMT "\n", octets(a));
    bits = ip4addr(s, &a, &np);
    if (!bits) printf(" addr: err tail=`%s'\n", np);
    else printf(" addr: " IPFMT " tail=`%s'\n", octets(a), np);

    bits = ip4cidr(s, &a, NULL);
    if (!bits)
      printf(" cidr: err\n");
    else
      printf(" cidr: bits=%u ip=" IPFMT "\n", bits, octets(a));
    bits = ip4cidr(argv[i], &a, &np);
    if (!bits)
      printf(" cidr: err tail=`%s'\n", np);
    else
      printf(" cidr: bits=%u ip=" IPFMT " tail=`%s'\n",
             bits, octets(a), np);
    b = ~ip4mask(bits);
    if (a & b) puts("err");

    bits = ip4range(s, &a, &b, NULL);
    if (!bits) printf(" range: err\n");
    else
      printf(" range: " IPFMT "-" IPFMT "\n", octets(a), octets(b));
    bits = ip4range(s, &a, &b, &np);
    if (!bits) printf(" range: err tail=`%s'\n", np);
    else
      printf(" range: " IPFMT "-" IPFMT " tail=`%s'\n",
             octets(a), octets(b), np);

   }
  return 0;
}

#endif
