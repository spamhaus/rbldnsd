/* IP4 address parsing routines
 */

#include "ip4addr.h"

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((c) - '0')

/* cret(): returns v if last byte is \0, or else
 * either sets *np to point to the last byte and
 * returns v, or return -1 */
#define cret(v, np, s) ((np) ? *(np) = (char*)(s), (v) : *(s) ? -1 : (v))
/* eret(): returns -1 and sets *np if np is non-NULL */
#define eret(np, s) ((np) ? *(np) = (char*)(s), -1 : -1)

static int ip4mbits(const char *s, char **np) {
  /* helper routine for ip4cidr() and ip4range() */
  int bits;
  if (!digit(*s))
    return eret(np, s - 1);
  bits = d2n(*s++);
  while(digit(*s))
    if ((bits = bits * 10 + d2n(*s++)) > 32)
      return eret(np, s - 1);
  /*if (!bits) return eret(np, s - 1); allow /0 mask too */
  return cret(bits, np, s);
}

/* parse a prefix, return # of bits (8,16,24 or 32)
 * or <0 on error.  Can't return 0. */
int ip4prefix(const char *s, ip4addr_t *ap, char **np) {
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

/* Parse ip4 CIDR range in `s', store base
 * in *ap and return number of bits (may be 0)
 * or <0 on error.
 * To zero hostpart:
 *  *ap &= ip4mask(bits)
 * where bits is the return value
 */

int ip4cidr(const char *s, ip4addr_t *ap, char **np) {
  int bits = ip4prefix(s, ap, (char**)&s);
  if (bits < 0)		/* error */
    return eret(np, s);
  else if (*s == '/')	/* probably /bits */
    return ip4mbits(s + 1, np);
  else if (bits == 8)	/* disallow bare numbers */
    return eret(np, s);
  else
    return cret(bits, np, s);
}

/* Parse ip4 range or CIDR in `s',
 * store start in *ap and end in *bp,
 * return
 *   bits (may be 0) if that was CIDR or prefix,
 *   32 if plain range,
 *   <0 on error.
 * *ap may have non-zero hostpart on
 * return and should be adjusted as
 *   *ap &= ip4mask(bits)
 * where bits is the return value.
 */

int ip4range(const char *s, ip4addr_t *ap, ip4addr_t *bp, char **np) {
  int bits = ip4prefix(s, ap, (char**)&s);

  if (bits < 0)
    return eret(np, s);
  else if (*s == '-') {	/* a-z */
    int bbits = ip4prefix(s + 1, bp, (char**)&s);
    if (bbits < 0) return eret(np, s);
    if (bbits == 8) { /* treat 127.0.0.1-2 as 127.0.0.1-127.0.0.2 */
      *bp = (*bp >> (bits - 8)) | (*ap & ip4mask(bits - 8));
      bbits = bits;
    }
    else if (bbits != bits)
      /* disallow weird stuff like 1.2-1.2.3.4 */
      return eret(np, s);
    if (bbits != 32) /* complete last octets */
      *bp |= ~ip4mask(bbits);
    if (*ap > *bp) return eret(np, s);
    return cret(32, np, s);
  }
  else {
    if (*s == '/') {	/* /bits */
      bits = ip4mbits(s + 1, (char**)&s);
      if (bits < 0) return eret(np, s);
    }
    else if (bits == 8)
      /* disallow bare numbers - use /8 */
      return eret(np, s);
    *bp = *ap | ~ip4mask(bits);
    return cret(bits, np, s);
  }
}

/* traditional inet_aton/inet_addr.  Werid:
 *   127.1 = 127.0.0.1
 *   1 = 0.0.0.1!!! - but here we go...
 * return #bits in _prefix_ (8,16,24 or 32), or <0 on error.
 */
int ip4addr(const char *s, ip4addr_t *ap, char **np) {
  int bits = ip4prefix(s, ap, np);
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
  int bits;
  char *np;

#define octets(x) (x)>>24,((x)>>16)&255,((x)>>8)&255,(x)&255
#define IPFMT "%u.%u.%u.%u"

  for(i = 1; i < argc; ++i) {
    char *s = argv[i];
    printf("%s:\n", s);

#define PFX   " pfx  : bits=%d "
#define ADDR  " addr : bits=%d "
#define CIDR  " cidr : bits=%d "
#define RANGE " range: bits=%d "
#define HP(a,bits) (a & ~ip4mask(bits) ? " (non-zero hostpart)" : "")

    bits = ip4prefix(s, &a, NULL);
    if (bits < 0) printf(" pfx  : err\n");
    else printf(" pfx  : bits=%d " IPFMT "\n", bits, octets(a));
    bits = ip4prefix(s, &a, &np);
    if (bits < 0) printf(" pfx  : err tail=`%s'\n", np);
    else
      printf(" pfx  : bits=%d " IPFMT " tail=`%s'\n", bits, octets(a), np);

    bits = ip4addr(s, &a, NULL);
    if (bits < 0) printf(" addr : err\n");
    else printf(" addr : bits=%d " IPFMT "\n", bits, octets(a));
    bits = ip4addr(s, &a, &np);
    if (bits < 0) printf(" addr : err tail=`%s'\n", np);
    else printf(" addr : bits=%d " IPFMT " tail=`%s'\n", bits, octets(a), np);

    bits = ip4cidr(s, &a, NULL);
    if (bits < 0) printf(" cidr : err\n");
    else
      printf(" cidr : bits=%d " IPFMT "%s\n", bits, octets(a), HP(a,bits));
    bits = ip4cidr(argv[i], &a, &np);
    if (bits < 0) printf(" cidr : err tail=`%s'\n", np);
    else
      printf(" cidr : bits=%d " IPFMT " " IPFMT " tail=`%s'%s\n",
             bits, octets(a), octets(a&ip4mask(bits)), np, HP(a,bits));

    bits = ip4range(s, &a, &b, NULL);
    if (bits < 0) printf(" range: err\n");
    else
      printf(" range: bits=%d " IPFMT "-" IPFMT "%s\n",
             bits, octets(a), octets(b), HP(a,bits));
    bits = ip4range(s, &a, &b, &np);
    if (bits < 0) printf(" range: err tail=`%s'\n", np);
    else
      printf(" range: bits=%d " IPFMT "-" IPFMT " tail=`%s'%s\n",
             bits, octets(a), octets(b), np, HP(a,bits));

  }
  return 0;
}

#endif
