/* IPv6 address-related routines
 */

#include "ip6addr.h"
#include <string.h>
#include <stdio.h>

#define digit(x) ((x)>='0'&&(x)<='9')
#define d2n(x) ((x)-'0')

/* parse address (prefix) in a form ffff:ffff:ffff:ffff:...
 * granularity (bits) is 16, so the routine will return
 * 16, 32, 48, 64, ... _bits_ on output or <0 on error.
 * "an" is the max amount of bytes (not bits!) to store in *ap,
 * should be even (2, 4, 6, 8, ...) and should be at least 2.
 * The routine does support shortcuts like ffff::ffff.
 */
int ip6prefix(const char *s, ip6oct_t ap[IP6ADDR_FULL], char **np) {
  static signed char hex_table[] = { /* map ascii to hex nibble value */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  };
  unsigned bytes = 0;     /* number of bytes we filled in ap so far */
  int zstart = -1;        /* location of "::", if any */
  int ret = -1;

  /* memset is better be done here instead of zeroing the tail,
   * since it's faster to zerofill full words.
   * We may even change that to a by-word loop, since all
   * addresses are aligned properly anyway */
  memset(ap, 0, IP6ADDR_FULL);

  if (s[0] == ':' && s[1] == ':') {
    zstart = 0;
    s += 2;
  }

  /* loop by semicolon-separated 2-byte (4 hex digits) fields */
  for(;;) {
    unsigned v = 0;		/* 2-byte (4 hex digit) field */
    const char *ss = s;		/* save `s' value */

    while ((*s & '\x80') == 0) {
      int nibble = hex_table[(unsigned)*s];
      if (nibble < 0)
        break;                  /* not a hex digit */
      v = (v << 4) + nibble;
      if (v > 0xffff)		/* a field can't be > 0xffff */
        break;
      ++s;
    }
    if (ss == s || v > 0xffff)	/* if no field has been consumed */
      break;
    ap[bytes++] = v >> 8;
    ap[bytes++] = v & 0xff;
    if (*s != ':' || bytes + 2 > IP6ADDR_FULL) {
      ret = bytes * 8;
      break;
    }
    ++s;
    if (zstart < 0 && *s == ':') {
      zstart = bytes;
      ++s;
    }
  }

  if (zstart >= 0) {
    /* expand the "::" */
    unsigned nzeros = IP6ADDR_FULL - bytes;
    if (nzeros == 0)
      ret = -1;                 /* illegal - no space for zeros */
    else {
      memmove(&ap[zstart + nzeros], &ap[zstart], bytes - zstart);
      memset(&ap[zstart], 0, nzeros);
      ret = 8 * IP6ADDR_FULL;
    }
  }

  if (np)
    *np = (char*)s;
  else if (*s)
    /* no success return if no 'tail' (np) pointer is given
     * and the tail isn't empty */
    ret = -1;
  return ret;
}

/* Parse ip6 CIDR range in `s', store base
 * in *ap (of size an bytes) and return number
 * of _bits_ (may be 0) or <0 on error.
 */
int ip6cidr(const char *s, ip6oct_t ap[IP6ADDR_FULL], char **np) {
  int bits = ip6prefix(s, ap, (char**)&s);

  if (bits >= 0 && *s == '/') {	/* parse /bits CIDR range */
    ++s;
    if (!digit(*s))
      bits = -1;
    else {
      bits = d2n(*s++);
      while(digit(*s))
        if ((bits = bits * 10 + d2n(*s++)) > 128) {
          bits = -1;
          break;
        }
    }
  }
  else if (bits == 16)
    bits = -1;			/* disallow bare number */

  if (np)
    *np = (char*)s;
  else if (*s)
    bits = -1;
  return bits;
}

int ip6mask(const ip6oct_t *ap, ip6oct_t *bp, unsigned n, unsigned bits) {
  unsigned i;
  int r = 0;

  i = bits / 8;
  bits %= 8;

  /* copy head */
  if (bp && bp != ap)
    memcpy(bp, ap, i < n ? i : n);

  /* check the middle byte */
  if (i < n && bits) {
    if (ap[i] & (0xff >> bits))
      r = 1;
    if (bp)
      bp[i] = ap[i] & (0xff << (8 - bits));
    ++i;
  }

  /* check-n-zero tail */
  while(i < n) {
    if (ap[i])
      r = 1;
    if (bp)
      bp[i] = 0;
    ++i;
  }

  return r;
}

const char *ip6atos(const ip6oct_t *ap, unsigned an) {
  static char buf[(4+1)*8+1];
  unsigned awords = an / 2;
  char *bp = buf;
  unsigned nzeros = 0, zstart = 0, i;

  if (awords > IP6ADDR_FULL / 2)
    awords = IP6ADDR_FULL / 2;

  /* find longest string of repeated zero words */
  for (i = 0; i + nzeros < IP6ADDR_FULL / 2; i++) {
    unsigned nz;                 /* count zero words */
    for (nz = 0; i + nz < awords; nz++)
      if (ap[2 * (i + nz)] != 0 || ap[2 * (i + nz) + 1] != 0)
        break;
    if (i + nz == awords)
      nz += IP6ADDR_FULL / 2 - awords;

    if (nz > 1 && nz > nzeros) {
      nzeros = nz;
      zstart = i;
    }
  }

  for (i = 0; i < zstart; i++)
    bp += sprintf(bp, ":%x", (((unsigned)ap[2*i]) << 8) + ap[2*i+1]);
  if (nzeros) {
    *bp++ = ':';
    if (zstart == 0)
      *bp++ = ':';                /* leading "::" */
    if (zstart + nzeros == IP6ADDR_FULL / 2)
      *bp++ = ':';                /* trailing "::" */
  }
  for (i += nzeros; i < awords; i++)
    bp += sprintf(bp, ":%x", (((unsigned)ap[2*i]) << 8) + ap[2*i+1]);
  for (; i < IP6ADDR_FULL / 2; i++) {
    *bp++ = ':';
    *bp++ = '0';
  }
  *bp = '\0';
  return buf + 1;
}

#ifdef TEST
#include <stdlib.h>

/* our own version of assert()
 *
 * (mostly so that checks still happen even when compiled with
 * -DNDEBUG)
 */
#define CHECK(expr) ((expr) ? (void) 0 : report_failure(#expr, __LINE__))

static void
report_failure(const char *expr, unsigned line)
{
  printf("%s:%u: check `%s' failed\n", __FILE__, line, expr);
  abort();
}

int main(int argc, char **argv) {
  int i;
  ip6oct_t a[IP6ADDR_FULL];
  int bits;
  char *np;


#define ip6tos(a,bits) (bits < 0 ? "err" : ip6atos(a,sizeof(a)))

  for(i = 1; i < argc; ++i) {
    char *s = argv[i];
    printf("%s:\n", s);

    bits = ip6prefix(s, a, NULL);
    printf(" pfx: %s/%d\n", ip6tos(a, bits), bits);
    bits = ip6prefix(s, a, &np);
    printf(" pfx: %s/%d tail=`%s'\n", ip6tos(a, bits), bits, np);

    bits = ip6cidr(s, a, NULL);
    printf("cidr: %s/%d\n", ip6tos(a, bits), bits);
    bits = ip6cidr(s, a, &np);
    printf("cidr: %s/%d tail=`%s'\n", ip6tos(a, bits), bits, np);
    if (bits >= 0) {
      bits = ip6mask(a, a, IP6ADDR_FULL, bits);
      printf("mask: %s (host=%d)\n", ip6atos(a, sizeof(a)), bits);
    }
  }

  CHECK(ip6prefix("::1", a, NULL) == 128);
  CHECK(strcmp(ip6atos(a, 128), "::1") == 0);

  CHECK(ip6prefix("1::", a, NULL) == 128);
  CHECK(strcmp(ip6atos(a, 128), "1::") == 0);

  CHECK(ip6prefix("1::4:0:0:0:8", a, NULL) == 128);
  CHECK(strcmp(ip6atos(a, 128), "1:0:0:4::8") == 0);

  return 0;
}

#endif
