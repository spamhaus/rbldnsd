/* $Id$
 * ip4set dataset type: IP4 addresses (ranges), with A and TXT
 * values for every individual entry.  More flexible than
 * ip4set but requires more memory.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

definedstype(ip4set, DSTF_IP4REV, "set of (ip4, value) pairs");

struct entry {
  ip4addr_t addr;	/* key: IP address */
  const char *rr;	/* A and TXT RRs */
};

struct dataset {
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated (only for loading) */
  struct entry *e[4];	/* entries */
  const char *def_rr;	/* default A and TXT RRs */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

static void ds_ip4set_free(struct dataset *ds) {
  if (ds) {
    if (ds->e[E32]) free(ds->e[E32]);
    if (ds->e[E24]) free(ds->e[E24]);
    if (ds->e[E16]) free(ds->e[E16]);
    if (ds->e[E08]) free(ds->e[E08]);
    free(ds);
  }
}

static int
ds_ip4set_addent(struct dataset *ds, unsigned idx,
                 ip4addr_t a, unsigned count,
                 const char *rr) {
  struct entry *e = ds->e[idx];
  ip4addr_t step = 1 << (idx << 3);

  if (ds->n[idx] + count > ds->a[idx]) {
    do ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    while(ds->n[idx] + count > ds->a[idx]);
    e = trealloc(struct entry, e, ds->a[idx]);
    if (!e)
      return 0;
    ds->e[idx] = e;
  }

  e += ds->n[idx];
  ds->n[idx] += count;
  for(; count--; a += step, ++e) {
    e->addr = a;
    e->rr = rr;
  }

  return 1;
}

static int
ds_ip4set_parseline(struct zonedataset *zds, char *s, int lineno) {
  struct dataset *ds = zds->zds_ds;
  ip4addr_t a, b;
  const char *rr;
  unsigned rrl;

  int not;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(s, &rr, def_rr))) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (!(ds->def_rr = mp_dmemdup(&zds->zds_mp, rr, rrl)))
      return 0;
    return 1;
  }

  if (*s == '!') {
    not = 1;
    do ++s;
    while(*s == ' ' || *s == '\t');
  }
  else
    not = 0;
  if (!ip4parse_range(s, &a, &b, &s) ||
      (*s && *s != ' ' && *s != '\t' && *s != '#' && *s != ':')) {
    dswarn(lineno, "invalid address");
    return 1;
  }
  if (not)
    rr = NULL;
  else {
    skipspace(s);
    if (!*s)
      rr = ds->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, ds->def_rr))) {
      dswarn(lineno, "invalid value");
      return 1;
    }
    else if (!(rr = mp_dmemdup(&zds->zds_mp, rr, rrl)))
      return 0;
  }

  /*XXX some comments about funny ip4range_expand et al */

#define fn(idx,start,count) ds_ip4set_addent(ds, idx, start, count, rr)

/* helper macro for ip4range_expand:
 * deal with last octet, shifting a and b when done
 */
#define ip4range_expand_octet(bits)			\
  if ((a | 255u) >= b) {				\
    if ((a ^ b) == 255u)				\
      return fn((bits>>3)+1, a<<bits, 1);		\
    else						\
      return fn(bits>>3, a<<bits, b - a + 1);		\
  }							\
  if (a & 255u) {					\
    if (!fn(bits>>3, a<<bits, 256u - (a & 255u)))	\
      return 0;						\
    a = (a >> 8) + 1;					\
  }							\
  else							\
    a >>= 8;						\
  if ((b & 255u) != 255u) {				\
    if (!fn((bits>>3), (b & ~255u)<<bits, (b&255u)+1))	\
      return 0;						\
    b = (b >> 8) - 1;					\
  }							\
  else							\
    b >>= 8

  ip4range_expand_octet(0);
  ip4range_expand_octet(8);
  ip4range_expand_octet(16);
  return fn(3, a << 24, b - a + 1);

}

static int ds_ip4set_load(struct zonedataset *zds, FILE *f) {
  zds->zds_ds->def_rr = def_rr;
  return readdslines(f, zds, ds_ip4set_parseline);
}

static struct dataset *ds_ip4set_alloc() {
  return tzalloc(struct dataset);
}

static int ds_ip4set_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 4; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) \
       a->addr < b->addr ? 1 : \
       a->addr > b->addr ? 0 : \
       a->rr < b->rr
#   include "qsort.c"

#define ip4set_eeq(a,b) a.addr == b.addr && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], ip4set_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e32/24/16/8=%u/%u/%u/%u",
          ds->n[E32], ds->n[E24], ds->n[E16], ds->n[E08]);
  return 1;
}

static const struct entry *
ds_ip4set_find(const struct entry *e, int b, ip4addr_t q) {
  int a = 0, m;
  --b;
  while(a <= b) {
    if (e[(m = (a + b) >> 1)].addr == q) {
      const struct entry *p = e + m - 1;
      while(p >= e && p->addr == q)
        --p;
      return p + 1;
    }
    else if (e[m].addr < q) a = m + 1;
    else b = m - 1;
  }
  return NULL;
}

static int
ds_ip4set_query(const struct zonedataset *zds, const struct dnsquery *qry,
                struct dnspacket *pkt) {
  const struct dataset *ds = zds->zds_ds;
  ip4addr_t q = qry->q_ip4;
  ip4addr_t f;
  const struct entry *e, *t;
  const char *ipsubst;

  if (!qry->q_ip4valid) return 0;

#define try(i,mask) \
 (ds->n[i] && \
  (t = ds->e[i] + ds->n[i], \
   e = ds_ip4set_find(ds->e[i], ds->n[i], (f = q & mask))) != NULL)

  if (!try(E32, 0xffffffff) &&
      !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) &&
      !try(E08, 0xff000000))
    return 0;

  if (!e->rr) return 0;		/* exclusion */

  ipsubst = (qry->q_tflag & NSQUERY_TXT) ? ip4atos(q) : NULL;
  do addrr_a_txt(pkt, qry->q_tflag, e->rr, ipsubst, zds);
  while(++e < t && e->addr == f);

  return 1;
}
