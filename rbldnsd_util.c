/* Common utility routines for rbldnsd.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "rbldnsd.h"
#include "mempool.h"

int
readzlines(FILE *f,struct zonedata *z,
           int (*zlpfn)(struct zonedata *z,
                        char *line, int lineno, int llines)) {
  char buf[512], *line, *eol;
  int lineno = 0, llineno = 0, noeol = 0;
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
        zwarn(lineno, "long line (truncated)");
      noeol = 1; /* mark it to be read above */
    }
    /* skip whitespace */
    line = buf;
    while(*line == ' ' || *line == '\t')
      ++line;
    while(eol >= line && (*eol == ' ' || *eol == '\t'))
      --eol;
    eol[1] = '\0';
    if (line[0] && line[0] != '#')
      if (!zlpfn(z, line, lineno, llineno++))
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

ip4addr_t dntoip4addr(const unsigned char *q) {
  ip4addr_t a = 0, o;
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o;
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 8;
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 16;
  if ((q = dnotoa(q, &o)) == NULL) return 0; a |= o << 24;
  return *q == 0 ? a : 0;
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

const char *mp_edstrdup(struct mempool *mp, const char *str) {
  str = mp_dstrdup(mp, str);
  if (!str) oom();
  return str;
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
