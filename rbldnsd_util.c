/* $Id$
 * Common utility routines for rbldnsd.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "rbldnsd.h"
#include "mempool.h"

#define skipspace(s) while(*s == ' ' || *s == '\t') ++s

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((c) - '0') 

char *parse_uint32(unsigned char *s, u_int32_t *np) {
  unsigned n = 0;
  if (!digit(*s))
    return NULL;
  do { 
    if (n > 0xffffffffu / 10) return 0;
    if (n * 10 > 0xffffffffu - d2n(*s)) return 0;
    n = n * 10 + d2n(*s++);
  } while(digit(*s));
  *np = n;
  skipspace(s);
  return s;
}

char *parse_dn(char *s, unsigned char *dn, unsigned *dnlenp) {
  char *n = s;
  unsigned l;
  while(*n && *n != ' ' && *n != '\t') ++n;
  if (*n) *n++ = '\0';
  if (!*s) return NULL;
  if ((l = dns_ptodn(s, dn, DNS_MAXDN)) == 0)
    return NULL;
  dns_dntol(dn, dn);
  if (dnlenp) *dnlenp = l;
  skipspace(n);
  return n;
}

static int
zds_special(struct zonedataset *zds, char *line) {

  if ((line[0] == 's' || line[0] == 'S') &&
      (line[1] == 'o' || line[1] == 'O') &&
      (line[2] == 'a' || line[2] == 'A') &&
      (line[3] == ' ' || line[3] == '\t')) {

    /* SOA record */
    struct zonesoa *zsoa = &zds->zds_zsoa;
    unsigned n;
    u_int32_t v;
    unsigned char *bp;

    if (zsoa->zsoa_valid)
      return 1; /* ignore if already set */

    line += 4;
    skipspace(line);

    if (!(line = parse_dn(line, zsoa->zsoa_odn + 1, &n))) return 0;
    zsoa->zsoa_odn[0] = n;
    if (!(line = parse_dn(line, zsoa->zsoa_pdn + 1, &n))) return 0;
    zsoa->zsoa_pdn[0] = n;

    for(n = 0, bp = zsoa->zsoa_n; n < 5; ++n) {
      if (!(line = parse_uint32(line, &v))) return 0;
      *bp++ = v >> 24; *bp++ = v >> 16; *bp++ = v >> 8; *bp++ = v;
    }

    if (*line) return 0;

    zsoa->zsoa_valid = 1;

    return 1;
  }

  if ((line[0] == 'n' || line[0] == 'N') &&
      (line[1] == 's' || line[1] == 'S') &&
      (line[2] == ' ' || line[2] == '\t')) {

     struct zonens *zns, **znsp;
     unsigned char dn[DNS_MAXDN+1];
     unsigned n;

     line += 3;
     skipspace(line);

     if (!(line = parse_dn(line, dn + 1, &n))) return 0;
     dn[0] = (unsigned char)n++;

     zns = (struct zonens *)emalloc(sizeof(struct zonens) + n);
     if (!zns) return 0;
     memcpy(zns->zns_dn, dn, n);
     zns->zns_dn = (unsigned char*)(zns + 1);

     znsp = &zds->zds_ns;
     while(*znsp) znsp = &(*znsp)->zns_next;
     *znsp = zns;
     zns->zns_next = NULL;

     return 1;
  }

#if 0
  if ((line[0] == 't' || line[0] == 'T') &&
      (line[1] == 't' || line[1] == 'T') &&
      (line[1] == 'l' || line[1] == 'L') &&
      (line[1] == ' ' || line[1] == '\t')) {
    /* ttl in a zone */
    return 0;
  }
#endif

  return 0;
}

int
readdslines(FILE *f, struct zonedataset *zds,
            int (*dslpfn)(struct dataset *ds, char *line, int lineno)) {
  char buf[512], *line, *eol;
  int lineno = 0, noeol = 0;
  while(fgets(buf, sizeof(buf), f)) {
    eol = buf + strlen(buf) - 1;
    if (eol < buf) /* can this happen? */
      continue;
    if (noeol) { /* read parts of long line up to \n */
      if (*eol == '\n')
        noeol = 0;
      continue;
    }
    ++lineno;
    if (*eol == '\n')
      --eol;
    else {
      if (!feof(f))
        dswarn(lineno, "long line (truncated)");
      noeol = 1; /* mark it to be read above */
    }
    /* skip whitespace */
    line = buf;
    while(*line == ' ' || *line == '\t')
      ++line;
    while(eol >= line && (*eol == ' ' || *eol == '\t'))
      --eol;
    eol[1] = '\0';
    if (line[0] == '$' ||
        ((line[0] == '#' || line[0] == ':') && line[1] == '$')) {
      int r = zds_special(zds, line[0] == '$' ? line + 1 : line + 2);
      if (!r)
        dswarn(lineno, "invalid or unrecognized special entry");
      else if (r < 0)
        return 0;
      continue;
    }
    if (line[0] && line[0] != '#')
      if (!dslpfn(zds->zds_ds, line, lineno))
        return 0;
  }
  return 1;
}

/* helper routine for dntoip4addr() */

static const unsigned char *dnotoa(const unsigned char *q, unsigned *ap) {
  if (*q < 1 || *q > 3) return NULL;
  if (q[1] < '0' || q[1] > '9') return NULL;
  *ap = q[1] - '0';
  if (*q == 1) return q + 2;
  if (q[2] < '0' || q[2] > '9') return NULL;
  *ap = *ap * 10 + (q[2] - '0');
  if (*q == 2) return q + 3;
  if (q[3] < '0' || q[3] > '9') return NULL;
  *ap = *ap * 10 + (q[3] - '0');
  return *ap > 255 ? NULL : q + 4;
}

/* parse DN (as in 4.3.2.1.in-addr.arpa) to ip4addr_t */

unsigned dntoip4addr(const unsigned char *q, ip4addr_t *ap) {
  ip4addr_t a = 0, o;
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o;
  if (!*q) { *ap = a << 24; return 1; }
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 8;
  if (!*q) { *ap = a << 16; return 2; }
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 16;
  if (!*q) { *ap = a << 8; return 3; }
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 24;
  if (!*q) { *ap = a; return 4; }
  return 0;
}

int addrtxt(char *str, ip4addr_t *ap, char **txtp) {
  while(*str == ' ' || *str == '\t') ++str;
  if (*str == ':') {
    unsigned bits = ip4addr(str + 1, ap, &str);
    if (!*ap || !bits) return 0;
    if (bits == 8)
      *ap |= IP4A_LOOPBACK; /* only last digit in 127.0.0.x */
    while(*str == ' ' || *str == '\t') ++str;
    if (*str == ':')
      ++str;
    else if (*str != '\0' && *str != '#' && *str != '\0')
      return 0;
    while(*str == ' ' || *str == '\t') ++str;
  }
  else
    *ap = 0;
  if (*str == '#' || *str == '\0')
    *txtp = NULL;
  else {
    *txtp = str;
    if (strlen(str) >= 255)
      (str)[254] = '\0'; /* limited by DNS */
  }
  return 1;
}

void *emalloc(unsigned size) {
  void *ptr = malloc(size);
  if (!ptr)
    oom();
  return ptr;
}

void *ezalloc(unsigned size) {
  void *ptr = calloc(1, size);
  if (!ptr)
    oom();
  return ptr;
}

void *erealloc(void *ptr, unsigned size) {
  void *nptr = realloc(ptr, size);
  if (!nptr)
    oom();
  return nptr;
}

char *estrdup(const char *str) {
  char *s = strdup(str);
  if (!s) oom();
  return s;
}

void *mp_ealloc(struct mempool *mp, unsigned size) {
  void *p = mp_alloc(mp, size);
  if (!p) oom();
  return p;
}

char *mp_estrdup(struct mempool *mp, const char *str) {
  str = mp_strdup(mp, str);
  if (!str) oom();
  return (char*)str;
}

void *mp_ememdup(struct mempool *mp, const void *buf, unsigned len) {
  buf = mp_memdup(mp, buf, len);
  if (!buf) oom();
  return (void*)buf;
}

const char *mp_edstrdup(struct mempool *mp, const char *str) {
  str = mp_dstrdup(mp, str);
  if (!str) oom();
  return str;
}

const void *mp_edmemdup(struct mempool *mp, const void *buf, unsigned len) {
  buf = mp_dmemdup(mp, buf, len);
  if (!buf) oom();
  return buf;
}

/* what a mess... this routine is to work around various snprintf
 * implementations.  It never return <1 or value greather than
 * size of buffer: i.e. it returns number of chars _actually written_
 * to a buffer.
 * Maybe replace this with an alternative (simplistic) implementation,
 * only %d/%u/%s, with additional %S to print untrusted data replacing
 * control chars with something sane, and to print `...' for arguments
 * that aren't fit (e.g. "%.5s", "1234567" will print `12...') ?
 */

int vssprintf(char *buf, int bufsz, const char *fmt, va_list ap) {
  int r = vsnprintf(buf, bufsz, fmt, ap);
  return r < 0 ? 0 : r >= bufsz ? bufsz - 1 : r;
}

int ssprintf(char *buf, int bufsz, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bufsz = vssprintf(buf, bufsz, fmt, ap);
  va_end(ap);
  return bufsz;
}
