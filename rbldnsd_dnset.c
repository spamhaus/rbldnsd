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

definedstype(dnset, 0, "set of domain names");

/*
 * We store all domain names in a sorted array, using binary
 * search to find an entry.  There are two similar arrays -
 * for plain entries and for wildcard entries - with all
 * variables indexed by EP and EW.
 */

struct entry {
  unsigned char *lrdn; /* reverseDN key, mp-allocated, length-1 first */
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
#define EP 0			/* plain entry */
#define EW 1			/* wildcard entry */

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
  if (!(line = parse_dn(line, dn, &dnlen)) || dnlen == 1) {
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
  if (!(e->lrdn = (unsigned char*)mp_ealloc(&ds->mp, dnlen + 1))) return 0;
  e->lrdn[0] = (unsigned char)(dnlen - 1);
  dns_dnreverse(dn, e->lrdn + 1, dnlen);
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

#define min(a,b) ((a)<(b)?(a):(b))

static int ds_dnset_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 2; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) \
   memcmp(a->lrdn + 1, b->lrdn + 1, min(a->lrdn[0], b->lrdn[0]) + 1) < 0
#   include "qsort.c"

#define dnset_eeq(a,b) memcmp(a.lrdn, b.lrdn, a.lrdn[0]) == 0
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], dnset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e/w=%u/%u", ds->n[EP], ds->n[EW]);
  return 1;
}

/* entry->lrdn[0] is total length of a dn MINUS ONE.
 * `dnlen' is length of rdn, again minus one byte.
 * This is in order to be able to look up beginning
 * of `rdn' easily: we don't look at last terminating
 * byte, but compare lengths instead, as when looking
 * beginning of `rdn', next label will not be empty.
 * `sub' will be set to 1 if some entry in array
 * starts with `rdn' (i.e. some subdomain of `rdn'
 * is listed) - this is important since we should
 * not return NXDOMAIN in a case when we have listed
 * some subdomain of query domain.
 */

static int
ds_dnset_find(const struct entry *e, int n,
              const unsigned char *rdn, unsigned dnlen,
              int *sub) {
  int a = 0, b = n - 1, m, r;
  while(a <= b) {
    const struct entry *t = e + (m = (a + b) >> 1);
    r = memcmp(t->lrdn + 1, rdn, min(t->lrdn[0], dnlen));
    if (r < 0) a = m + 1;
    else if (r > 0) b = m - 1;
    else if (t->lrdn[0] == dnlen) return 1;
    else if (t->lrdn[0] < dnlen) a = m + 1;
    else b = m - 1;
  }
  if (sub && a < n && dnlen < (e += a)->lrdn[0] &&
      memcmp(rdn, e->lrdn + 1, dnlen) == 0)
    *sub = 1;
  return 0;
}

static int
ds_dnset_query(const struct dataset *ds,
               const struct dnsquery *query, unsigned qtyp,
               struct dnspacket *packet) {
  const unsigned char *rdn = query->q_rdn;
  unsigned qlen = query->q_dnlen - 1;
  unsigned qlab = query->q_dnlab;
  int sub = 0;
  if (!qlab)
    return 0;
  if (qlab > ds->maxlab[EP] ||
      !ds_dnset_find(ds->e[EP], ds->n[EP], rdn, qlen, &sub)) {
    /* try wildcard; require at least 1 label on the left */
    const unsigned char *dn = query->q_dn;
    do
      --qlab, qlen -= *dn + 1, dn += *dn + 1;
    while(qlab > ds->maxlab[EW]);
    for(;;) {
      if (qlab < ds->minlab[EW]) {
        if (sub) return 1;
        if (query->q_dnlab > ds->maxlab[EW]) return 0;
        if (ds_dnset_find(ds->e[EW], ds->n[EW], rdn, query->q_dnlen - 1, &sub))
          return 1;
        return sub;
      }
      if (ds_dnset_find(ds->e[EW], ds->n[EW], rdn, qlen, NULL))
        break;
      qlen -= *dn + 1;
      dn += *dn + 1;
      --qlab;
    }
  }
  if (qtyp & NSQUERY_A) addrec_a(packet, ds->r_a);
  if (ds->r_txt && (qtyp & NSQUERY_TXT)) {
    char name[DNS_MAXDOMAIN+1];
    dns_dntop(query->q_dn, name, sizeof(name));
    addrec_txt(packet, ds->r_txt, name);
  }
  return 1;
}
