/* $Id$
 * generic zone, simplified bind format.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definezonetype(generic, NSQUERY_ANY, "generic simplified bind-format");

struct entry {
  const unsigned char *dn; /* mp-allocated */
  unsigned short dtyp;	/* data (query) type */
  unsigned short dsiz;	/* data size */
  void *data;		/* data of size dsize, mp-allocated */
};

/* note: we use two bytes in dtyp.
 * lsb is a type in DNS, e.g. DNS_T_A: all types fit in one byte.
 * msb is our NSQUERY_* flag: see definitions in rbldnsd.h
 * Once DNS types will not fit in one byte, this code should be rewviwed.
 * Good news for _now_ is that the whole thing (type + size) fits nicely
 * in 4 bytes (2 shorts), so entry size is 12 bytes (will be 16 if anything
 * will be added).
 */

struct zonedata {
  unsigned n;		/* number of entries */
  unsigned a;		/* entries allocated (only when loading) */
  struct entry *e;	/* entries */
#if 0
  unsigned minlab;	/* min level of labels */
  unsigned maxlab;	/* max level of labels */
#endif
  struct mempool mp;	/* mempool for domain names and RR data */
};

static void generic_free(struct zonedata *z) {
  if (z) {
    mp_free(&z->mp);
    if (z->e) free(z->e);
    free(z);
  }
}

#define skipsp(s) while(*s == ' ' || *s == '\t') ++s
#define endword(s,err) \
 while(*s && *s != ' ' && *s != '\t') ++s; \
 if (*s) *s++ = '\0'

#define digit(c) ((c) >= '0' && (c) <= '9')
#define d2n(c) ((c) - '0')

static char *ssatoi(unsigned char *s, u_int32_t *np) {
  unsigned n = 0;
  skipsp(s);
  if (!digit(*s))
    return NULL;
  do {
    if (n > 0xffffffffu / 10) return 0;
    if (n * 10 > 0xffffffffu - d2n(*s)) return 0;
    n = n * 10 + d2n(*s++);
  } while(digit(*s));
  *np = n;
  return s;
}

static char *getdn(char *s, unsigned char *dn, unsigned dnsz, unsigned *len) {
  char *n = s;
  endword(n, NULL);
  return (*len = dns_ptodn(s, dn, dnsz)) ? n : NULL;
}

static int generic_parseany(struct zonedata *z, char *line) {
  struct entry *e;
  char *t;
  unsigned short dtyp, dsiz;
  unsigned n;
  char data[400];

  /* allocate new entry */
  e = z->e;
  if (z->n >= z->a) {
    z->a = z->a ? z->a << 1 : 8;
    e = (struct entry *)erealloc(e, z->a * sizeof(*e));
    if (!e) return 0;
    z->e = e;
  }
  e += z->n;

  /* dn */
  if (!(line = getdn(line, data, DNS_MAXDN, &n))) return -1;
  if (strcmp(data, "\1@") == 0)
    data[0] = '\0';
  if (!(e->dn = (const unsigned char*)mp_edstrdup(&z->mp, data)))
    return 0;
#if 0
  n = dns_dnlabels(e->dn);
  if (z->maxlab < n) z->maxlab = n;
  if (z->minlab > n) z->minlab = n;
#endif
 
  skipsp(line);

  /* type */
  t = line;
  while(*line != ' ' && *line != '\t')
    if (!*line) return -1;
    else { *line = dns_dnlc(*line); ++line; }
  *line++ = '\0';
  skipsp(line);

  if (strcmp(t, "a") == 0) {
    ip4addr_t a;
    dtyp = NSQUERY_A | DNS_T_A;
    if (!ip4addr(line, &a, &line)) return -1;
    dsiz = 4;
    a = htonl(a);
    memcpy(data, &a, 4);
  }

  else if (strcmp(t, "txt") == 0) {
    dtyp = NSQUERY_TXT | DNS_T_TXT;
    dsiz = strlen(line);
    if (dsiz >= 2 && line[0] == '"' && line[dsiz-1] == '"')
      ++line, dsiz -= 2;
    if (dsiz > 254) dsiz = 254;
    data[0] = (char)dsiz;
    memcpy(data+1, line, dsiz);
    ++dsiz;
  }

  else if (strcmp(t, "ns") == 0) {
    dtyp = NSQUERY_NS | DNS_T_NS;
    if (!(line = getdn(line, data, DNS_MAXDN, &n)) || *line) return -1;
    dsiz = n;
  }

  else if (strcmp(t, "soa") == 0) {
    u_int32_t v;
    unsigned c;

    dtyp = NSQUERY_SOA | DNS_T_SOA;

    if (!(line = getdn(line, data, DNS_MAXDN, &n))) return -1;
    skipsp(line);
    dsiz = n;
    if (!(line = getdn(line, data + dsiz, DNS_MAXDN, &n))) return -1;
    skipsp(line);
    dsiz += n;

    for(c = 0; c < 5; ++c) {
      if (!(line = ssatoi(line, &v))) return -1;
      v = htonl(v);
      memcpy(data + dsiz, &v, 4);
      dsiz += 4;
    }
    if (*line) return -1;
  }
  else
    return -1;

  if (!(e->data = mp_alloc(&z->mp, dsiz)))
    return 0;
  e->dtyp = dtyp;
  e->dsiz = dsiz;
  memcpy(e->data, data, dsiz);
  ++z->n;

  return 1;
}

static int
generic_parseline(struct zonedata *z, char *line,
                  int lineno, int UNUSED unused_llines) {
  int r = generic_parseany(z, line);
  if (r < 0) {
    zwarn(lineno, "invalid/unrecognized entry");
    return 1;
  }
  else if (!r)
    return 0;
  else
    return 1;
}

static int generic_load(struct zonedata *z, FILE *f) {
  return readzlines(f, z, generic_parseline);
}

static struct zonedata *generic_alloc() {
  struct zonedata *z = (struct zonedata *)emalloc(sizeof(*z));
  if (z)
    memset(z, 0, sizeof(*z));
  return z;
}

static inline int generic_lt(const struct entry *a, const struct entry *b) {
  int r = strcmp(a->dn, b->dn);
  return
     r < 0 ? 1 :
     r > 0 ? 0 :
     a->dtyp < b->dtyp;
}

static int generic_finish(struct zonedata *z) {
  if (z->n) {

#   define QSORT_TYPE struct entry
#   define QSORT_BASE z->e
#   define QSORT_NELT z->n
#   define QSORT_LT(a,b) generic_lt(a,b)
#   include "qsort.c"

    /* collect all equal DNs to point to the same place */
    { struct entry *e, *t;
      for(e = z->e, t = e + z->n - 1; e < t; ++e)
        if (e[0].dn != e[1].dn && strcmp(e[0].dn, e[1].dn) == 0)
          e[1].dn = e[0].dn;
    }
    SHRINK_ARRAY(struct entry, z->e, z->n, z->a);
  }
  zloaded("e=%u", z->n);
  return 1;
}

static const struct entry *
generic_find(const struct entry *e, int b, const unsigned char *q) {
  int a = 0, m, r;
  while(a <= b) {
    if (!(r = strcmp(e[(m = (a + b) >> 1)].dn, q))) {
      const struct entry *p = e + m;
      q = (p--)->dn;
      while(p >= e && p->dn == q)
        --p;
      return p + 1;
    }
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return NULL;
}

static int
generic_query(const struct zonedata *const z, struct dnspacket *p,
              const unsigned char *const query, unsigned qtyp)
{
  const struct entry *e, *t;
  const unsigned char *dn;
  if (!(e = generic_find(z->e, z->n - 1, query)))
    return 0;
  t = z->e + z->n;
  dn = e->dn;
  do
    if (qtyp & e->dtyp)
      addrec_any(p, e->dtyp & 0xff, e->data, e->dsiz);
  while(++e < t && e->dn == dn);
  return 1;
}
