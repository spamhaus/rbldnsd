/* $Id$
 * ip4vset dataset type: IP4 addresses (ranges), with A and TXT
 * values for every individual entry.  More flexible than
 * ip4set but requires more memory.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definedstype(ip4vset, DSTF_IP4REV, "set of (ip4, value) pairs");

struct entry {
  ip4addr_t addr;	/* key */
  ip4addr_t r_a;	/* result: addr */
  const char *r_txt;	/* result: txt (mempool) */
};

struct dataset {
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated (only for loading) */
  struct entry *e[4];	/* entries */
  struct mempool mp;	/* mempool for TXT RRs */
  ip4addr_t r_a;	/* default A RR */
  const char *r_txt;	/* default txt (mempool) */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

static void ds_ip4vset_free(struct dataset *ds) {
  if (ds) {
    mp_free(&ds->mp);
    if (ds->e[E32]) free(ds->e[E32]);
    if (ds->e[E24]) free(ds->e[E24]);
    if (ds->e[E16]) free(ds->e[E16]);
    if (ds->e[E08]) free(ds->e[E08]);
    free(ds);
  }
}

static int
ds_ip4vset_addent(struct dataset *ds, unsigned idx,
                  ip4addr_t a, unsigned count,
                  ip4addr_t r_a, const char *r_txt) {
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
    e->r_a = r_a;
    e->r_txt = r_txt;
  }

  return 1;
}

static int
ds_ip4vset_parseline(struct dataset *ds, char *line, int lineno) {
  ip4addr_t a, b;
  char *p;
  ip4addr_t r_a;
  const char *r_txt;
  int not;

  if (line[0] == ':') {
    if (!addrtxt(line, &a, &p)) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) ds->r_a = a;
    if (!p) ds->r_txt = NULL;
    else if (!(ds->r_txt = mp_edstrdup(&ds->mp, p)))
      return 0;
    return 1;
  }

  if (*line == '!') {
    not = 1;
    do ++line;
    while(*line == ' ' || *line == '\t');
  }
  else
    not = 0;
  if (!ip4parse_range(line, &a, &b, &p) ||
      (*p != '\0' && *p != ' ' && *p != '\t' && *p != '#' && *p != ':')) {
    dswarn(lineno, "invalid address");
    return 1;
  }
  if (not)
    r_a = 0;
  else {
    if (!addrtxt(p, &r_a, &p)) {
      dswarn(lineno, "invalid value");
      return 1;
    }
    if (!r_a)
      r_a = ds->r_a;
  }

  if (not) r_txt = NULL;
  else if (!p) r_txt = ds->r_txt;
  else if (!(r_txt = mp_edstrdup(&ds->mp, p))) return 0;

#define fn(idx,start,count) ds_ip4vset_addent(ds, idx, start, count, r_a, r_txt)
  ip4range_expand(a, b, fn);
}

static int ds_ip4vset_load(struct zonedataset *zds, FILE *f) {
  zds->zds_ds->r_a = R_A_DEFAULT;
  zds->zds_ds->r_txt = NULL;
  return readdslines(f, zds, ds_ip4vset_parseline);
}

static struct dataset *ds_ip4vset_alloc() {
  return tzalloc(struct dataset);
}

static int ds_ip4vset_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 4; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) \
       a->addr < b->addr ? 1 : \
       a->addr > b->addr ? 0 : \
       a->r_a < b->r_a
#   include "qsort.c"

#define ip4vset_eeq(a,b) a.addr == b.addr && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], ip4vset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e32/24/16/8=%u/%u/%u/%u",
          ds->n[E32], ds->n[E24], ds->n[E16], ds->n[E08]);
  return 1;
}

static const struct entry *
ds_ip4vset_find(const struct entry *e, int b, ip4addr_t q) {
  int a = 0, m;
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
ds_ip4vset_find_masked(const struct entry *e, int b,
                       ip4addr_t q, ip4addr_t mask) {
  int a = 0, m;
  while(a <= b) {
    if ((e[(m = (a + b) >> 1)].addr & mask) == q) return 1;
    else if ((e[m].addr & mask) < q) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_ip4vset_query(const struct dataset *ds,
                 const struct dnsquery *query, unsigned qtyp,
                 struct dnspacket *packet) {
  ip4addr_t q = query->q_ip4;
  ip4addr_t f;
  const struct entry *e, *t;
  const char *ipsubst;

  if (query->q_ip4oct != 4) {
    unsigned n, l;

    if (!(l = query->q_ip4oct)) return 0;

    /* we can't return NXDOMAIN for 3.2.1.bl.example.com -
     * e.g. if 4.3.2.1.bl.example.com exists */
    f = ip4mask(l * 8);
    n = E32;
    do 
      if (ds_ip4vset_find_masked(ds->e[n], ds->n[n] - 1, q, f))
        return 1;
    while (++n < 4 - l);
    while(n <= E08) {
      q &= f;
      if (ds_ip4vset_find(ds->e[n], ds->n[n] - 1, q)) return 1;
      f <<= 8;
      ++n;
    }
    return 0;
  }

  /* valid 4-octets IP */

#define try(i,mask) \
 (ds->n[i] && \
  (t = ds->e[i] + ds->n[i], \
   e = ds_ip4vset_find(ds->e[i], ds->n[i] - 1, (f = q & mask))) != NULL)

  if (!try(E32, 0xffffffff) &&
      !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) &&
      !try(E08, 0xff000000))
    return 0;

  if (!e->r_a) return 0;

  ipsubst = (qtyp & NSQUERY_TXT) ? ip4atos(q) : NULL;
  do {
    if (qtyp & NSQUERY_A)
      addrec_a(packet, e->r_a);
    if (e->r_txt && qtyp & NSQUERY_TXT)
      addrec_txt(packet, e->r_txt, ipsubst);
  } while(++e < t && e->addr == f);

  return 1;
}
