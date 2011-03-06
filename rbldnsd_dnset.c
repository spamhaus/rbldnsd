/* Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct entry {
  const unsigned char *ldn;	/* DN key, mp-allocated, length byte first */
  const char *rr;		/* A and TXT RRs */
};

/*
 * We store all domain names in a sorted array, using binary
 * search to find an entry.
 */
struct dnarr {
  unsigned n;			/* number of entries */
  unsigned a;			/* entries allocated so far */
  unsigned h;			/* hint: number of ent to alloc next time */
  struct entry *e;		/* (sorted) array of entries */
  unsigned minlab, maxlab;	/* min and max no. of labels in array */
};

/* There are two similar arrays -
 * for plain entries and for wildcard entries.
 */

struct dsdata {
  struct dnarr p;		/* plain entries */
  struct dnarr w;		/* wildcard entries */
  const char *def_rr;		/* default A and TXT RRs */
};

definedstype(dnset, 0, "set of (domain name, value) pairs");

static void ds_dnset_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  unsigned hp = dsd->p.h, hw = dsd->w.h;
  if (dsd->p.e) free(dsd->p.e);
  if (dsd->w.e) free(dsd->w.e);
  memset(dsd, 0, sizeof(*dsd));
  dsd->p.minlab = dsd->w.minlab = DNS_MAXDN;
  dsd->p.h = hp; dsd->w.h = hw;
}

static void ds_dnset_start(struct dataset *ds) {
  ds->ds_dsd->def_rr = def_rr;
}

static int
ds_dnset_addent(struct dnarr *arr,
                const unsigned char *ldn, const char *rr,
                unsigned dnlab) {
  struct entry *e;

  e = arr->e;
  if (arr->n >= arr->a) { /* expand array */
    arr->a = arr->a ? arr->a << 1 :
               arr->h ? arr->h : 64;
    e = trealloc(struct entry, e, arr->a);
    if (!e) return 0;
    arr->e = e;
  }

  /* fill up an entry */
  e += arr->n++;
  e->ldn = ldn;
  e->rr = rr;

  /* adjust min/max #labels */
  if (arr->maxlab < dnlab) arr->maxlab = dnlab;
  if (arr->minlab > dnlab) arr->minlab = dnlab;

  return 1;
}

static int
ds_dnset_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned char dn[DNS_MAXDN];
  const char *rr;
  unsigned char *ldn;
  unsigned dnlen, size;
  int not, iswild, isplain;

  if (*s == ':') {		/* default entry */
    if (!(size = parse_a_txt(s, &rr, def_rr, dsc)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, size)))
      return 0;
    return 1;
  }

  /* check negation */
  if (*s == '!') {
    not = 1;
    ++s; SKIPSPACE(s);
  }
  else
    not = 0;

  /* check for wildcard: .xxx or *.xxx */
  if (*s == '.') { iswild = 1; isplain = 1; ++s; }
  else if (s[0] == '*' && s[1] == '.') { iswild = 1; isplain = 0; s += 2; }
  else { iswild = 0; isplain = 1; }

  /* disallow emptry DN to be listed (i.e. "all"?) */
  if (!(s = parse_dn(s, dn, &dnlen)) || dnlen == 1) {
    dswarn(dsc, "invalid domain name");
    return 1;
  }

  dns_dntol(dn, dn);		/* lowercase */

  if (not)
    rr = NULL;			/* negation entry */
  else {			/* else parse rest */
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))	/* use default if none given */
      rr = dsd->def_rr;
    else if (!(size = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      return 1;
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, size)))
      return 0;
  }

  ldn = (unsigned char*)mp_alloc(ds->ds_mp, dnlen + 1, 0);
  if (!ldn)
    return 0;
  ldn[0] = (unsigned char)(dnlen - 1);
  memcpy(ldn + 1, dn, dnlen);

  dnlen = dns_dnlabels(dn);
  if (isplain && !ds_dnset_addent(&dsd->p, ldn, rr, dnlen))
    return 0;
  if (iswild && !ds_dnset_addent(&dsd->w, ldn, rr, dnlen))
    return 0;

  return 1;
}

static int ds_dnset_lt(const struct entry *a, const struct entry *b) {
  int r;
  if (a->ldn[0] < b->ldn[0]) return 1;
  if (a->ldn[0] > b->ldn[0]) return 0;
  r = memcmp(a->ldn + 1, b->ldn + 1, a->ldn[0]);
  return
     r < 0 ? 1 :
     r > 0 ? 0 :
     a->rr < b->rr;
}

static void ds_dnset_finish_arr(struct dnarr *arr) {
  if (!arr->n) {
    arr->h = 0;
    return;
  }
  arr->h = arr->a;
  while((arr->h >> 1) >= arr->n)
    arr->h >>= 1;

# define QSORT_TYPE struct entry
# define QSORT_BASE arr->e
# define QSORT_NELT arr->n
# define QSORT_LT(a,b) ds_dnset_lt(a,b)
# include "qsort.c"

  /* we make all the same DNs point to one string for faster searches */
  { register struct entry *e, *t;
    for(e = arr->e, t = e + arr->n - 1; e < t; ++e)
      if (memcmp(e[0].ldn, e[1].ldn, e[0].ldn[0] + 1) == 0)
        e[1].ldn = e[0].ldn;
  }
#define dnset_eeq(a,b) a.ldn == b.ldn && rrs_equal(a,b)
  REMOVE_DUPS(struct entry, arr->e, arr->n, dnset_eeq);
  SHRINK_ARRAY(struct entry, arr->e, arr->n, arr->a);
}

static void ds_dnset_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ds_dnset_finish_arr(&dsd->p);
  ds_dnset_finish_arr(&dsd->w);
  dsloaded(dsc, "e/w=%u/%u", dsd->p.n, dsd->w.n);
}

static const struct entry *
ds_dnset_find(const struct entry *e, int n,
              const unsigned char *dn, unsigned dnlen0) {
  int a = 0, b = n - 1, m, r;

  /* binary search */
  while(a <= b) {
    /* middle entry */
    const struct entry *t = e + (m = (a + b) >> 1);
    if (t->ldn[0] < dnlen0)		/* middle entry < dn */
      a = m + 1;			/* look in last half */
    else if (t->ldn[0] > dnlen0)	/* middle entry > dn */
      b = m - 1;			/* look in first half */
    /* lengths match, compare the DN itself */
    else if ((r = memcmp(t->ldn + 1, dn, dnlen0)) == 0) {
      /* found exact match, seek back to
       * first entry with this domain name */
      dn = (t--)->ldn;
      while(t >= e && t->ldn == dn)
        --t;
      return t + 1;
    }
    else if (r < 0)			/* middle entry < dn */
      a = m + 1;			/* look in last half */
    else				/* middle entry > dn */
      b = m - 1;			/* look in first half */
  }

  return NULL;			/* not found */
}

static int
ds_dnset_query(const struct dataset *ds, const struct dnsqinfo *qi,
               struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const unsigned char *dn = qi->qi_dn;
  unsigned qlen0 = qi->qi_dnlen0;
  unsigned qlab = qi->qi_dnlab;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];

  if (!qlab) return 0;		/* do not match empty dn */
  check_query_overwrites(qi);

  if (qlab > dsd->p.maxlab 	/* if we have less labels, search unnec. */
      || qlab < dsd->p.minlab	/* ditto for more */
      || !(e = ds_dnset_find(dsd->p.e, dsd->p.n, dn, qlen0))) {

    /* try wildcard */

    /* remove labels until number of labels in query is greather
     * than we have in wildcard array, but remove at least 1 label
     * for wildcard itself. */
    do
      --qlab, qlen0 -= *dn + 1, dn += *dn + 1;
    while(qlab > dsd->w.maxlab);

    /* now, lookup every so long dn in wildcard array */
    for(;;) {

      if (qlab < dsd->w.minlab)
        /* oh, number of labels in query become less than
         * minimum we have listed.  Nothing to search anymore */
        return 0;

      if ((e = ds_dnset_find(dsd->w.e, dsd->w.n, dn, qlen0)))
        break;			/* found, listed */

      /* remove next label at the end of rdn */
      qlen0 -= *dn + 1;
      dn += *dn + 1;
      --qlab;

    }
    t = dsd->w.e + dsd->w.n;

  }
  else
    t = dsd->p.e + dsd->p.n;

  if (!e->rr) return 0;	/* exclusion */

  dn = e->ldn;
  if (qi->qi_tflag & NSQUERY_TXT)
    dns_dntop(e->ldn + 1, name, sizeof(name));
  do addrr_a_txt(pkt, qi->qi_tflag, e->rr, name, ds);
  while(++e < t && e->ldn == dn);

  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

static void
ds_dnset_dump(const struct dataset *ds,
              const unsigned char UNUSED *unused_odn,
              FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+4];
  for (e = dsd->p.e, t = e + dsd->p.n; e < t; ++e) {
    dns_dntop(e->ldn + 1, name, sizeof(name));
    dump_a_txt(name, e->rr, name, ds, f);
  }
  name[0] = '*'; name[1] = '.';
  for (e = dsd->w.e, t = e + dsd->w.n; e < t; ++e) {
    dns_dntop(e->ldn + 1, name + 2, sizeof(name) - 2);
    dump_a_txt(name, e->rr, name + 2, ds, f);
  }
}

#endif
