/* $Id$
 * Common utility routines for rbldnsd.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include "rbldnsd.h"

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((unsigned)((c) - '0'))

static char *parse_uint32_s(char *s, unsigned *np) {
  unsigned char *t = (unsigned char*)s;
  unsigned n = 0;
  if (!digit(*t))
    return NULL;
  do { 
    if (n > 0xffffffffu / 10) return 0;
    if (n * 10 > 0xffffffffu - d2n(*t)) return 0;
    n = n * 10 + d2n(*t++);
  } while(digit(*t));
  *np = n;
  return (char*)t;
}

char *parse_uint32(char *s, unsigned *np) {
  if (!(s = parse_uint32_s(s, np))) return NULL;
  if (*s) {
    if (!ISSPACE(*s)) return NULL;
    ++s; SKIPSPACE(s);
  }
  return s;
}

char *parse_uint32_nb(char *s, unsigned char nb[4]) {
  unsigned n;
  if (!(s = parse_uint32(s, &n))) return NULL;
  PACK32(nb, n);
  return s;
}

char *parse_time(char *s, unsigned *tp) {
  unsigned m = 1;
  if (!(s = parse_uint32_s(s, tp))) return NULL;
  switch(*s) {
    case 'w': case 'W': m *= 7;		/* week */
    case 'd': case 'D': m *= 24;	/* day */
    case 'h': case 'H': m *= 60;	/* hours */
    case 'm': case 'M': m *= 60;	/* minues */
      if (0xffffffffu / m < *tp) return NULL;
      *tp *= m;
    case 's': case 'S':			/* secounds */
      ++s;
      break;
  }
  if (*s && *s != ':') {
    if (!ISSPACE(*s)) return NULL;
    ++s; SKIPSPACE(s);
  }
  return s;
}

char *parse_time_nb(char *s, unsigned char nb[4]) {
  unsigned t;
  if (!(s = parse_time(s, &t))) return NULL;
  PACK32(nb, t);
  return s;
}

char *parse_ttl(char *s, unsigned *ttlp, unsigned defttl) {
  s = parse_time(s, ttlp);
  if (*ttlp == 0)
    *ttlp = defttl;
  else if (min_ttl && *ttlp < min_ttl)
    *ttlp = min_ttl;
  else if (max_ttl && *ttlp > max_ttl)
    *ttlp = max_ttl;
  return s;
}

char *parse_dn(char *s, unsigned char *dn, unsigned *dnlenp) {
  char *n = s;
  unsigned l;
  while(*n && !ISSPACE(*n)) ++n;
  if (*n) *n++ = '\0';
  if (!*s) return NULL;
  if ((l = dns_ptodn(s, dn, DNS_MAXDN)) == 0)
    return NULL;
  if (dnlenp) *dnlenp = l;
  SKIPSPACE(n);
  return n;
}

int readdslines(FILE *f, struct dataset *ds, struct dsctx *dsc) {
#define bufsiz 8192
  char _buf[bufsiz+4], *line, *eol;
#define buf (_buf+4)  /* keep room for 4 IP octets in addrtxt() */
  int noeol = 0;
  struct dataset *dscur = ds;
  ds_linefn_t *linefn = dscur->ds_type->dst_linefn;

  while(fgets(buf, bufsiz, f)) {
    eol = buf + strlen(buf) - 1;
    if (eol < buf) /* can this happen? */
      continue;
    if (noeol) { /* read parts of long line up to \n */
      if (*eol == '\n')
        noeol = 0;
      continue;
    }
    ++dsc->dsc_lineno;
    if (*eol == '\n')
      --eol;
    else if (feof(f)) {
      dslog(LOG_WARNING, dsc, "incomplete last line (ignored)");
      break;
    }
    else {
      dswarn(dsc, "long line (truncated)");
      noeol = 1; /* mark it to be read above */
    }
    /* skip whitespace */
    line = buf;
    SKIPSPACE(line);
    while(eol >= line && ISSPACE(*eol))
      --eol;
    eol[1] = '\0';
    if (line[0] == '$' ||
        ((ISCOMMENT(line[0]) || line[0] == ':') && line[1] == '$')) {
      int r = ds_special(ds, line[0] == '$' ? line + 1 : line + 2, dsc);
      if (!r)
        dswarn(dsc, "invalid or unrecognized special entry");
      else if (r < 0)
        return 0;
      dscur = dsc->dsc_subset ? dsc->dsc_subset : ds;
      linefn = dscur->ds_type->dst_linefn;
      continue;
    }
    if (line[0] && !ISCOMMENT(line[0]))
      if (!linefn(dscur, line, dsc))
        return 0;
  }
  return 1;
#undef buf
}

int parse_a_txt(char *str, const char **rrp, const char *def_rr,
                struct dsctx *dsc) {
  char *rr;
  static char rrbuf[4+256];	/*XXX static buffer */
  if (*str == ':') {
    ip4addr_t a;
    int bits = ip4addr(str + 1, &a, &str);
    if (!a || bits <= 0) {
      dswarn(dsc, "invalid A RR");
      return 0;
    }
    if (bits == 8)
      a |= IP4A_LOOPBACK; /* only last digit in 127.0.0.x */
    SKIPSPACE(str);
    if (*str == ':') {	/* A+TXT */
      ++str;
      SKIPSPACE(str);
      rr = (unsigned char*)str - 4;
      PACK32(rr, a);
    }
    else if (*str) {
      dswarn(dsc, "unrecognized value for an entry");
      return 0;
    }
    else {	/* only A - take TXT from default entry */
      unsigned tlen = strlen(def_rr+4);	/* tlen is <= 255 */
      rr = rrbuf;
      PACK32(rr, a);
      memcpy(rr+4, def_rr+4, tlen+1);
      *rrp = rr;
      return tlen + 5;
    }
  }
  else {
    rr = (unsigned char*)str - 4;
    memcpy(rr, def_rr, 4);
  }
  if (*str) {
    unsigned len = strlen(str);
    if (len > 255) {
      dswarn(dsc, "TXT RR truncated to 255 bytes");
      str += 255;
    }
    else
      str += len;
    *str = '\0';
  }
  *rrp = rr;
  return 1 + (str - rr);
}

unsigned unpack32(const unsigned char p[4]) {
  unsigned n = p[0];
  n = (n << 8) | p[1];
  n = (n << 8) | p[2];
  n = (n << 8) | p[3];
  return n;
}

#ifndef NO_MASTER_DUMP

void dump_ip4(ip4addr_t a, const char *rr, const struct dataset *ds, FILE *f) {
  char name[sizeof("255.255.254.255")];
  sprintf(name, "%u.%u.%u.%u", a&255, (a>>8)&255, (a>>16)&255, (a>>24));
  dump_a_txt(name, rr, ip4atos(a), ds, f);
}

static void
dump_ip4octets(FILE *f, unsigned idx, ip4addr_t a, unsigned cnt,
	       const char *rr, const struct dataset *ds) {
  char name[16];
  static const char * const fmt[4] = {
     "%u.%u.%u.%u", "*.%u.%u.%u", "*.%u.%u", "*.%u"
  };
  const unsigned bits = 8 * idx;
  for(;;) {
    sprintf(name, fmt[idx], a&255, (a>>8)&255, (a>>16)&255, (a>>24));
    dump_a_txt(name, rr, ip4atos(a<<bits), ds, f);
    if (!--cnt)
      break;
    ++a;
  }
}

void dump_ip4range(ip4addr_t a, ip4addr_t b, const char *rr,
		   const struct dataset *ds, FILE *f) {

#define fn(idx,start,count) \
	dump_ip4octets(f, idx, start, count, rr, ds)
#define ip4range_expand_octet(bits)               \
  if ((a | 255u) >= b) {                          \
    if (b - a == 255u)                            \
      fn((bits>>3)+1, a>>8, 1);                   \
    else                                          \
      fn(bits>>3, a, b - a + 1);                  \
    return;                                       \
  }                                               \
  if (a & 255u) {                                 \
    fn(bits>>3, a, 256u - (a & 255u));            \
    a = (a >> 8) + 1;                             \
  }                                               \
  else                                            \
    a >>= 8;                                      \
  if ((b & 255u) != 255u) {                       \
    fn((bits>>3), (b & ~255u), (b&255u)+1);       \
    b = (b >> 8) - 1;                             \
  }                                               \
  else                                            \
    b >>= 8

  ip4range_expand_octet(0);
  ip4range_expand_octet(8);
  ip4range_expand_octet(16);
  fn(3, a, b - a + 1);

#undef fn
#undef ip4range_expand_octet

}

#endif

/* implement TXT substitutions.
 * `sb' is a buffer where the result will be stored -
 * at least 255 + 3 characters long */
int txtsubst(char sb[TXTBUFSIZ], const char *txt,
	     const char *s0, const struct dataset *ds) {
  char *const *sn = ds->ds_subst;
  unsigned sl;
  char *const e = sb + 254;
  char *lp = sb;
  const char *s, *si;
  if (!s0) s0 = "$";
  while(lp < e) {
    if ((s = strchr(txt, '$')) == NULL)
      s = (char*)txt + strlen(txt);
    sl = s - txt;
    if (lp + sl > e)
      sl = e - lp;
    memcpy(lp, txt, sl);
    lp += sl;
    if (!*s++) break;
    if (*s == '$') { si = s++; sl = 1; }
    else if (*s >= '0' && *s <= '9') { /* $1 var */
      si = sn[*s - '0'];
      if (!si) { si = s - 1; sl = 2; }
      else sl = strlen(si);
      ++s;
    }
    else
      sl = strlen(si = s0);
    if (lp + sl > e) /* silently truncate TXT RR >255 bytes */
      sl = e - lp;
    memcpy(lp, si, sl);
    lp += sl;
    txt = s;
  }
  sl = lp - sb;
  if (sl > 254) sl = 254;
  return sl;
}

void
dump_a_txt(const char *name, const unsigned char *rr,
           const char *subst, const struct dataset *ds, FILE *f) {
  if (!rr)
    fprintf(f, "%s\tCNAME\texcluded\n", name);
  else {
    fprintf(f, "%s\tA\t%u.%u.%u.%u\n",
            name, rr[0], rr[1], rr[2], rr[3]);
    if (rr[4]) {
      char txt[TXTBUFSIZ];
      char *p, *n;
      txt[txtsubst(txt, rr + 4, subst, ds)] = '\0';
      fprintf(f, "\tTXT\t\"");
      for(p = txt; (n = strchr(p, '"')) != NULL; p = n + 1) {
        fwrite(p, 1, n - p, f);
        putc('\\', f); putc('"', f);
      }
      fprintf(f, "%s\"\n", p);
    }
  }
}

char *emalloc(unsigned size) {
  void *ptr = malloc(size);
  if (!ptr)
    oom();
  return ptr;
}

char *ezalloc(unsigned size) {
  void *ptr = calloc(1, size);
  if (!ptr)
    oom();
  return ptr;
}

char *erealloc(void *ptr, unsigned size) {
  void *nptr = realloc(ptr, size);
  if (!nptr)
    oom();
  return nptr;
}

char *ememdup(const void *buf, unsigned len) {
  char *b = emalloc(len);
  if (b)
    memcpy(b, buf, len);
  return b;
}

char *estrdup(const char *str) {
  return ememdup(str, strlen(str) + 1);
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
  return r < 0 ? 0 : r >= bufsz ? buf[bufsiz-1] = '\0', bufsz - 1 : r;
}

int ssprintf(char *buf, int bufsz, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  bufsz = vssprintf(buf, bufsz, fmt, ap);
  va_end(ap);
  return bufsz;
}

/* logging */

static void
vdslog(int level, struct dsctx *dsc, const char *fmt, va_list ap) {
  char buf[1024];
  int pl, l;
  if ((logto & LOGTO_STDOUT) ||
      (level <= LOG_WARNING && (logto & LOGTO_STDERR)))
    l = pl = ssprintf(buf, sizeof(buf), "%.30s: ", progname);
  else if (logto & LOGTO_SYSLOG)
    l = pl = 0;
  else
    return;
  if (dsc) {
    if (dsc->dsc_fname) {
      l += ssprintf(buf + l, sizeof(buf) - l, "file %.60s", dsc->dsc_fname);
      l += ssprintf(buf + l, sizeof(buf) - l,
                    dsc->dsc_lineno ? "(%d): " : ": ", dsc->dsc_lineno);
    }
    else {
      l += ssprintf(buf + l, sizeof(buf) - l, "%s:%.60s:",
                    dsc->dsc_ds->ds_type->dst_name, dsc->dsc_ds->ds_spec);
      if (dsc->dsc_subset) {
        l += ssprintf(buf + l, sizeof(buf) - l, "%s:",
                      dsc->dsc_subset->ds_type->dst_name);
	if (dsc->dsc_subset->ds_spec)
          l += ssprintf(buf + l, sizeof(buf) - l, "%s:",
                        dsc->dsc_subset->ds_spec);
      }
      l += ssprintf(buf + l, sizeof(buf) - l, " ");
    }
  }
  l += vssprintf(buf + l, sizeof(buf) - l, fmt, ap);
  if (logto & LOGTO_SYSLOG) {
    fmt = buf + pl;
    syslog(level, strchr(fmt, '%') ? "%s" : fmt, fmt);
  }
  buf[l++] = '\n';
  if (level <= LOG_WARNING) {
    if (logto & (LOGTO_STDERR|LOGTO_STDOUT))
      write(2, buf, l);
  }
  else if (logto & LOGTO_STDOUT)
    write(1, buf, l);
}

void dslog(int level, struct dsctx *dsl, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vdslog(level, dsl, fmt, ap);
  va_end(ap);
}

#define MAXWARN 5

void dswarn(struct dsctx *dsl, const char *fmt, ...) {
  if (++dsl->dsc_warns <= MAXWARN) { /* prevent syslog flood */
    va_list ap;
    va_start(ap, fmt);
    vdslog(LOG_WARNING, dsl, fmt, ap);
    va_end(ap);
  }
}

void dsloaded(struct dsctx *dsc, const char *fmt, ...) {
  va_list ap;
  if (dsc->dsc_warns > MAXWARN)
    dslog(LOG_WARNING, dsc, "%d more warnings suppressed",
          dsc->dsc_warns - MAXWARN);
  va_start(ap, fmt);
  if (dsc->dsc_subset)
     vdslog(LOG_INFO, dsc, fmt, ap);
  else {
    struct tm *tm = gmtime(&dsc->dsc_ds->ds_stamp);
    char buf[128];
    vssprintf(buf, sizeof(buf), fmt, ap);
    dslog(LOG_INFO, dsc, "%04d%02d%02d %02d%02d%02d: %s",
          tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec,
          buf);
  }
  va_end(ap);
}

void zlog(int level, const struct zone *zone, const char *fmt, ...) {
  va_list ap;
  char buf[128];
  char name[DNS_MAXDOMAIN+1];

  va_start(ap, fmt);
  vssprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  dns_dntop(zone->z_dn, name, sizeof(name));
  dslog(level, 0, "zone %.70s: %s", name, buf);
}
