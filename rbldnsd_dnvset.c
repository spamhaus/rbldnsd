/* $Id$
 * Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definedstype(dnvset, 0, "set of (domain name, value) pairs");

struct entry {
  const unsigned char *dn;	/* key, mp-allocated */
  ip4addr_t r_a;		/* A RR */
  const char *r_txt;		/* TXT RR, mp-allocated */
};

/* dataset and operations is the same as in rbldnsd_dnset,
 * except of instead array of just domain names we store array
 * of structures for each entry.  Also, we allow duplicated entries. */

struct dataset {
  unsigned n[2]; /* number of entries */
  unsigned a[2]; /* entries allocated (used only when loading) */
  struct entry *e[2]; /* entries: plain and wildcard */
  unsigned minlab[2]; /* min level of labels */
  unsigned maxlab[2]; /* max level of labels */
  struct mempool mp; /* mempool for domain names and TXT RRs */
  ip4addr_t r_a; /* default result: address */
  const char *r_txt; /* default result: text (mp-allocated) */
};

/* indexes */
#define EP 0
#define EW 1

static void ds_dnvset_free(struct dataset *ds) {
  if (ds) {
    mp_free(&ds->mp);
    if (ds->e[EP]) free(ds->e[EP]);
    if (ds->e[EW]) free(ds->e[EW]);
    free(ds);
  }
}

static int
ds_dnvset_parseline(struct dataset *ds, char *line, int lineno) {
  ip4addr_t a;
  unsigned char dn[DNS_MAXDN];
  struct entry *e;
  unsigned idx, dnlen;
  int not;

  if (line[0] == ':') {
    if (!addrtxt(line, &a, &line)) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) ds->r_a = a;
    if (!line) ds->r_txt = NULL;
    else if (!(ds->r_txt = mp_edstrdup(&ds->mp, line)))
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
  if (*line == '.') { idx = EW; ++line; }
  else if (line[0] == '*' && line[1] == '.') { idx = EW; line += 2; }
  else idx = EP;
  if (!(line = parse_dn(line, dn, &dnlen))) {
    dswarn(lineno, "invalid domain name");
    return 1;
  }
  dns_dntol(dn, dn);
  if (not)
    a = 0;
  else {
    if (!addrtxt(line, &a, &line)) {
      dswarn(lineno, "invalid value");
      return 1;
    }
    if (!a)
      a = ds->r_a;
  }

  e = ds->e[idx];
  if (ds->n[idx] >= ds->a[idx]) {
    ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    e = trealloc(struct entry, e, ds->a[idx]);
    if (!e) return 0;
    ds->e[idx] = e;
  }
  e += ds->n[idx]++;
  e->r_a = a;
  if (not) e->r_txt = NULL;
  else if (!line) e->r_txt = ds->r_txt;
  else if (!(e->r_txt = mp_edstrdup(&ds->mp, line))) return 0;
  if (!(e->dn = (const unsigned char*)mp_ememdup(&ds->mp, dn, dnlen)))
    return 0;
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;

  return 1;
}

static struct dataset *ds_dnvset_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds)
    ds->minlab[EP] = ds->minlab[EW] = 255;
  return ds;
}

static int ds_dnvset_load(struct zonedataset *zds, FILE *f) {
  zds->zds_ds->r_a = R_A_DEFAULT;
  zds->zds_ds->r_txt = NULL;
  return readdslines(f, zds, ds_dnvset_parseline);
}

static int ds_dnvset_lt(const struct entry *a, const struct entry *b) {
  int r = strcmp(a->dn, b->dn);
  return
     r < 0 ? 1 :
     r > 0 ? 0 :
     a->r_a < b->r_a;
}

static int ds_dnvset_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 2; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) ds_dnvset_lt(a,b)
#   include "qsort.c"

    /* we make all the same DNs point to one string for faster searches */
    { register struct entry *e, *t;
      for(e = ds->e[r], t = e + ds->n[r] - 1; e < t; ++e)
        if (e[0].dn != e[1].dn && strcmp(e[0].dn, e[1].dn) == 0)
          e[1].dn = e[0].dn;
    }
#define dnvset_eeq(a,b) a.dn == b.dn && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], dnvset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e/w=%u/%u", ds->n[EP], ds->n[EW]);
  return 1;
}

static const struct entry *
ds_dnvset_find(const struct entry *e, int b, const unsigned char *q) {
  int a = 0, m, r;
  while(a <= b) {
    if (!(r = strcmp(e[(m = (a + b) >> 1)].dn, q))) {
      const struct entry *p = e + m;
      q = (p--)->dn;
      while(p > e && p->dn == q)
        --p;
      return p + 1;
    }
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return NULL;
}

static int
ds_dnvset_query(const struct dataset *const ds, struct dnspacket *p,
             const unsigned char *const query, unsigned labels, unsigned qtyp)
{
  const unsigned char *dn = query;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];
  if (!labels)
    return 0;
  if (labels > ds->maxlab[EP] || labels < ds->minlab[EP] ||
      !(e = ds_dnvset_find(ds->e[EP], ds->n[EP] - 1, dn))) {
    /* try wildcard; require at least 1 label on the left */
    do
      --labels, dn += 1 + *dn;
    while(labels > ds->maxlab[EW]);
    for(;;) {
      if (labels < ds->minlab[EW]) return 0;
      if ((e = ds_dnvset_find(ds->e[EW], ds->n[EW]-1, dn)) != NULL) break;
      dn += 1 + *dn;
      --labels;
    }
    t = ds->e[EW] + ds->n[EW];
  }
  else
    t = ds->e[EP] + ds->n[EP];

  if (!e->r_a) return 0;

  dn = e->dn;
  if (qtyp & NSQUERY_TXT)
    dns_dntop(query, name, sizeof(name));
  do {
    if (qtyp & NSQUERY_A)
      addrec_a(p, e->r_a);
    if (ds->r_txt && qtyp & NSQUERY_TXT)
      addrec_txt(p, e->r_txt, name);
  } while(++e < t && e->dn == dn);

  return 1;
}
