/* $Id$
 * dataset type which consists of a set of (possible wildcarded)
 * domain names, all sharing the same (A,TXT) result.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definedstype(dnset, "set of domain names");

/*
 * We store all domain names in a sorted array, using binary
 * search to find an entry.  There are two similar arrays -
 * for plain entries and for wildcard entries - with all
 * variables indexed by EP and EW.
 */

struct entry {
  const unsigned char *dn; /* mp-allocated */
};

struct dataset {
  unsigned n[2];	/* number of entries */
  unsigned a[2];	/* entries allocated so far (for loading only) */
  int nfile;		/* file #: we read default only from first file */
  int defread;		/* defaults has been read */
  struct entry *e[2];	/* entries: plain and wildcard */
  unsigned minlab[2];	/* min level of labels */
  unsigned maxlab[2];	/* max level of labels */
  ip4addr_t r_a;	/* result: address */
  const char *r_txt;	/* result: text */
  struct mempool mp;	/* mempool for domain names */
  /* not strpool: we usually don't need to check dups */
};

/* indexes */
#define EP 0
#define EW 1

static void ds_dnset_free(struct dataset *ds) {
  if (ds) {
    mp_free(&ds->mp);
    if (ds->e[EP]) free(ds->e[EP]);
    if (ds->e[EW]) free(ds->e[EW]);
    free(ds);
  }
}

static int
ds_dnset_parseline(struct dataset *ds, char *line, int lineno) {
  unsigned char dn[DNS_MAXDN];
  unsigned idx, dnlen;
  struct entry *e;

  if (line[0] == ':') {
    if (ds->nfile > 1)
      return 1;
    if (ds->defread) {
      dswarn(lineno, "second default entry ignored");
      return 1;
    }
    if (!addrtxt(line, &ds->r_a, &line)) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (!ds->r_a) ds->r_a = R_A_DEFAULT;
    if (line && !(ds->r_txt = mp_estrdup(&ds->mp, line)))
      return 0;
    ds->defread = 1;
    return 1;
  }

  if (*line == '.') { idx = EW; ++line; }
  else if (*line == '*' && line[1] == '.') { idx = EW; line += 2; }
  else idx = EP;
  if (!(line = parse_dn(line, dn, &dnlen))) {
    dswarn(lineno, "invalid domain name");
    return 1;
  }
  dns_dntol(dn, dn);

  e = ds->e[idx];
  if (ds->n[idx] >= ds->a[idx]) {
    ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    e = trealloc(struct entry, e, ds->a[idx]);
    if (!e) return 0;
    ds->e[idx] = e;
  }
  e += ds->n[idx]++;
  if (!(e->dn = (const unsigned char*)mp_ememdup(&ds->mp, dn, dnlen))) return 0;
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;
 
  return 1;
}

static struct dataset *ds_dnset_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds) {
    ds->r_a = R_A_DEFAULT;
    ds->minlab[EP] = ds->minlab[EW] = 256;
  }
  return ds;
}

static int ds_dnset_load(struct zonedataset *zds, FILE *f) {
  ++zds->zds_ds->nfile;
  return readdslines(f, zds, ds_dnset_parseline);
}

static int ds_dnset_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 2; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) strcmp(a->dn, b->dn) < 0
#   include "qsort.c"

#define dnset_eeq(a,b) strcmp(a.dn, b.dn) == 0
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], dnset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e/w=%u/%u", ds->n[EP], ds->n[EW]);
  return 1;
}

static int
ds_dnset_find(const struct entry *e, int b, const unsigned char *q) {
  int a = 0, m, r;
  while(a <= b) {
    if (!(r = strcmp(e[(m = (a + b) >> 1)].dn, q))) return 1;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_dnset_query(const struct dataset *const ds, struct dnspacket *p,
               const unsigned char *const query, unsigned labels, unsigned qtyp)
{
  const unsigned char *dn = query;
  if (!labels)
    return 0;
  if (labels > ds->maxlab[EP] || labels < ds->minlab[EP] ||
      !ds_dnset_find(ds->e[EP], ds->n[EP] - 1, dn)) {
    /* try wildcard; require at least 1 label on the left */
    do
      --labels, dn += 1 + *dn;
    while(labels > ds->maxlab[EW]);
    for(;;) {
      if (labels < ds->minlab[EW]) return 0;
      if (ds_dnset_find(ds->e[EW], ds->n[EW]-1, dn)) break;
      dn += 1 + *dn;
      --labels;
    }
  }
  if (qtyp & NSQUERY_A) addrec_a(p, ds->r_a);
  if (ds->r_txt && (qtyp & NSQUERY_TXT)) {
    char name[DNS_MAXDOMAIN+1];
    dns_dntop(query, name, sizeof(name));
    addrec_txt(p, ds->r_txt, name);
  }
  return 1;
}

