/* $Id$
 * generic dataset, simplified bind format.
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

definedstype(generic, "generic simplified bind-format");

struct entry {
  const unsigned char *dn; /* mp-allocated */
  u_int16_t dtyp;	/* data (query) type */
  u_int16_t dsiz;	/* data size */
  unsigned char *data;	/* data of size dsize, mp-allocated */
};

/* note: we use two bytes in dtyp.
 * lsb is a type in DNS, e.g. DNS_T_A: all types fit in one byte.
 * msb is our NSQUERY_* flag: see definitions in rbldnsd.h
 * Once DNS types will not fit in one byte, this code should be rewviwed.
 * Good news for _now_ is that the whole thing (type + size) fits nicely
 * in 4 bytes (2 shorts), so entry size is 12 bytes (will be 16 if anything
 * will be added).
 */

struct dataset {
  unsigned n;		/* number of entries */
  unsigned a;		/* entries allocated (only when loading) */
  struct entry *e;	/* entries */
  unsigned minlab;	/* min level of labels */
  unsigned maxlab;	/* max level of labels */
  struct mempool mp;	/* mempool for domain names and RR data */
};

static void ds_generic_free(struct dataset *ds) {
  if (ds) {
    mp_free(&ds->mp);
    if (ds->e) free(ds->e);
    free(ds);
  }
}

static int ds_generic_parseany(struct dataset *ds, char *line) {
  struct entry *e;
  char *t;
  unsigned dtyp, dsiz;
  char data[DNS_MAXDN*2+10];
  char *dp;

  /* allocate new entry */
  e = ds->e;
  if (ds->n >= ds->a) {
    ds->a = ds->a ? ds->a << 1 : 8;
    e = trealloc(struct entry, e, ds->a);
    if (!e) return 0;
    ds->e = e;
  }
  e += ds->n;

  /* dn */
  if (!(line = parse_dn(line, data, &dsiz))) return -1;
  if (strcmp(data, "\1@") == 0) {
    data[0] = '\0';
    dsiz = 1;
  }
  if (!(e->dn = (const unsigned char*)mp_edmemdup(&ds->mp, data, dsiz)))
    return 0;

  skipspace(line);

  /* type */
  t = line;
  while(*line != ' ' && *line != '\t')
    if (!*line) return -1;
    else { *line = dns_dnlc(*line); ++line; }
  *line++ = '\0';
  skipspace(line);

  dp = data;

  if (strcmp(t, "a") == 0) {
    ip4addr_t a;
    dtyp = NSQUERY_A | DNS_T_A;
    if (!ip4addr(line, &a, &line)) return -1;
    a = htonl(a);
    memcpy(data, &a, 4);
    dsiz = 4;
  }

  else if (strcmp(t, "txt") == 0) {
    dtyp = NSQUERY_TXT | DNS_T_TXT;
    dsiz = strlen(line);
    if (dsiz >= 2 && line[0] == '"' && line[dsiz-1] == '"')
      ++line, dsiz -= 2;
    if (dsiz > 254) dsiz = 254;
    data[0] = (char)dsiz;
    memcpy(data+1, line, dsiz);
    dsiz += 1;
  }

  else if (strcmp(t, "ns") == 0) {
    dtyp = NSQUERY_NS | DNS_T_NS;
    if (!(line = parse_dn(line, data + 1, &dsiz))) return -1;
    if (*line) return -1;
    data[0] = (unsigned char)dsiz;
    ++dsiz;
  }

  else if (strcmp(t, "mx") == 0) {
    u_int16_t prio;
    u_int32_t v;
    dtyp = NSQUERY_MX | DNS_T_MX;
    if (!(line = parse_uint32(line, &v))) return -1;
    prio = htons(v); memcpy(data, &prio, 2); dp += 3;
    if (!(line = parse_dn(line, data + 3, &dsiz))) return -1;
    if (*line) return -1;
    data[2] = (unsigned char)dsiz;
    dsiz += 3;
  }

  else
    return -1;

  if (!(e->data = mp_alloc(&ds->mp, dsiz)))
    return 0;
  e->dtyp = dtyp;
  e->dsiz = dsiz;
  memcpy(e->data, data, dsiz);

  ++ds->n;
  dsiz = dns_dnlabels(e->dn);
  if (ds->minlab > dsiz) ds->minlab = dsiz;
  if (ds->maxlab < dsiz) ds->maxlab = dsiz;

  return 1;
}

static int
ds_generic_parseline(struct dataset *ds, char *line, int lineno) {
  int r = ds_generic_parseany(ds, line);
  if (r < 0) {
    dswarn(lineno, "invalid/unrecognized entry");
    return 1;
  }
  else if (!r)
    return 0;
  else
    return 1;
}

static int ds_generic_load(struct zonedataset *zds, FILE *f) {
  return readdslines(f, zds, ds_generic_parseline);
}

static struct dataset *ds_generic_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds)
    ds->minlab = DNS_MAXDN;
  return ds;
}

static inline int ds_generic_lt(const struct entry *a, const struct entry *b) {
  int r = strcmp(a->dn, b->dn);
  return
     r < 0 ? 1 :
     r > 0 ? 0 :
     a->dtyp < b->dtyp;
}

static int ds_generic_finish(struct dataset *ds) {
  if (ds->n) {

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e
#   define QSORT_NELT ds->n
#   define QSORT_LT(a,b) ds_generic_lt(a,b)
#   include "qsort.c"

    /* collect all equal DNs to point to the same place */
    { struct entry *e, *t;
      for(e = ds->e, t = e + ds->n - 1; e < t; ++e)
        if (e[0].dn != e[1].dn && strcmp(e[0].dn, e[1].dn) == 0)
          e[1].dn = e[0].dn;
    }
    SHRINK_ARRAY(struct entry, ds->e, ds->n, ds->a);
  }
  dsloaded("e=%u", ds->n);
  return 1;
}

static const struct entry *
ds_generic_find(const struct entry *e, int b, const unsigned char *q) {
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
ds_generic_query(const struct dataset *const ds, struct dnspacket *p,
                 const unsigned char *const query, unsigned labels,
                 unsigned qtyp)
{
  const struct entry *e, *t;
  const unsigned char *dn;
  if (labels > ds->minlab) return 0;
  /*XXX if we have a.b.c, but query is for b.c, we should NOT return NXDOMAIN */
  if (!(e = ds_generic_find(ds->e, ds->n - 1, query)))
    return 0;
  t = ds->e + ds->n;
  dn = e->dn;
  do {
    if (!(qtyp & e->dtyp))
      continue;
    switch(e->dtyp & 0xff) {
    case DNS_T_NS:
      addrec_ns(p, e->data + 1, e->data[0]);
      break;
    case DNS_T_MX:
      addrec_mx(p, e->data, e->data + 3, e->data[2]);
      break;
    default:
      addrec_any(p, e->dtyp & 0xff, e->data, e->dsiz);
      break;
    }
  } while(++e < t && e->dn == dn);
  return 1;
}
