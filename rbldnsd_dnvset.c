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
  unsigned char *lrdn;	/* reverseDN key, mp-allocated, length-1 first */
  ip4addr_t r_a;	/* A RR */
  const char *r_txt;	/* TXT RR, mp-allocated */
};

/* dataset and operations is the same as in rbldnsd_dnset,
 * except of instead array of just domain names we store array
 * of structures for each entry.  Also, we allow duplicated entries. */

struct dataset {
  unsigned n[2]; /* number of entries */
  unsigned a[2]; /* entries allocated (used only when loading) */
  struct entry *e[2]; /* entries: plain and wildcard */
  unsigned maxlab[2]; /* max level of labels */
  unsigned minlab[2]; /* min level of labels */
  struct mempool mp; /* mempool for domain names and TXT RRs */
  ip4addr_t r_a; /* default result: address */
  const char *r_txt; /* default result: text (mp-allocated) */
};

/* indexes */
#define EP 0			/* plain entry */
#define EW 1			/* wildcard entry */

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
  if (!(line = parse_dn(line, dn, &dnlen)) || dnlen == 1) {
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
  if (!(e->lrdn = (unsigned char*)mp_ealloc(&ds->mp, dnlen + 1)))
    return 0;
  e->lrdn[0] = (unsigned char)(dnlen - 1);
  dns_dnreverse(dn, e->lrdn + 1, dnlen);
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;

  return 1;
}

static struct dataset *ds_dnvset_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds)
    ds->minlab[EP] = ds->minlab[EW] = DNS_MAXDN;
  return ds;
}

static int ds_dnvset_load(struct zonedataset *zds, FILE *f) {
  zds->zds_ds->r_a = R_A_DEFAULT;
  zds->zds_ds->r_txt = NULL;
  return readdslines(f, zds, ds_dnvset_parseline);
}

#define min(a,b) ((a)<(b)?(a):(b))

static int ds_dnvset_lt(const struct entry *a, const struct entry *b) {
  int r = memcmp(a->lrdn + 1, b->lrdn + 1, min(a->lrdn[0], b->lrdn[0]) + 1);
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
        if (e[0].lrdn[0] == e[1].lrdn[0] &&
            memcmp(e[0].lrdn, e[1].lrdn, e[0].lrdn[0] + 1) == 0)
          e[1].lrdn = e[0].lrdn;
    }
#define dnvset_eeq(a,b) a.lrdn == b.lrdn && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], dnvset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e/w=%u/%u", ds->n[EP], ds->n[EW]);
  return 1;
}

/* see comments in dnset dataset code. dnvset is very similar */

static const struct entry *
ds_dnvset_find(const struct entry *e, int n,
               const unsigned char *rdn, unsigned dnlen,
               int *sub) {
  int a = 0, b = n - 1, m, r;
  while(a <= b) {
    const struct entry *t = e + (m = (a + b) >> 1);
    r = memcmp(t->lrdn + 1, rdn, min(t->lrdn[0], dnlen));
    if (r < 0) a = m + 1;
    else if (r > 0) b = m - 1;
    else if (t->lrdn[0] == dnlen) {
      /* found exact match, seek back to
       * first entry with this domain name */
      rdn = (t--)->lrdn;
      while(t > e && t->lrdn == rdn)
        --t;
      return t + 1;
    }
    else if (t->lrdn[0] < dnlen) a = m + 1;
    else b = m - 1;
  }
  if (sub && a < n && dnlen < (e += a)->lrdn[0] &&
      memcmp(rdn, e->lrdn + 1, dnlen) == 0)
    *sub = 1;
  return NULL;
}

static int
ds_dnvset_query(const struct dataset *ds, const struct dnsquery *query,
                struct dnspacket *packet) {
  const unsigned char *rdn = query->q_rdn;
  unsigned qlen = query->q_dnlen - 1;
  unsigned qlab = query->q_dnlab;
  int sub = 0;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];

  if (qlab > ds->maxlab[EP] ||
    !(e = ds_dnvset_find(ds->e[EP], ds->n[EP], rdn, qlen, &sub))) {
    /* try wildcard; require at least 1 label on the left */
    const unsigned char *dn = query->q_dn;
    do
      --qlab, qlen -= *dn + 1, dn += *dn + 1;
    while(qlab > ds->maxlab[EW]);
    for(;;) {
      if (qlab < ds->minlab[EW]) {
        if (sub) return 1;
        if (query->q_dnlab > ds->maxlab[EW]) return 0;
        if (ds_dnvset_find(ds->e[EW], ds->n[EW], rdn, query->q_dnlen - 1, &sub))
          return 1;
        return sub;
      }
      if ((e = ds_dnvset_find(ds->e[EW], ds->n[EW], rdn, qlen, NULL)))
        break;
      qlen -= *dn + 1;
      dn += *dn + 1;
      --qlab;
    }
    t = ds->e[EW] + ds->n[EW];
  }
  else
    t = ds->e[EP] + ds->n[EP];

  if (!e->r_a) return 0;

  rdn = e->lrdn;
  if (query->q_tflag & NSQUERY_TXT) {
    char dn[DNS_MAXDN];
    dns_dnreverse(e->lrdn + 1, dn, e->lrdn[0] + 1);
    dns_dntop(query->q_dn, name, sizeof(name));
  }
  do {
    if (query->q_tflag & NSQUERY_A)
      addrec_a(packet, e->r_a);
    if (ds->r_txt && (query->q_tflag & NSQUERY_TXT))
      addrec_txt(packet, e->r_txt, name);
  } while(++e < t && e->lrdn == rdn);

  return 1;
}
