/* $Id$
 * Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

definedstype(dnset, DSTF_DNREV, "set of (domain name, value) pairs");

struct entry {
  unsigned char *lrdn;	/* reverseDN key, mp-allocated, length-1 first */
  const char *rr;	/* A and TXT RRs */
};

/*
 * We store all domain names in a sorted array, using binary
 * search to find an entry.  There are two similar arrays -
 * for plain entries and for wildcard entries - with all
 * variables indexed by EP and EW.
 */

struct dataset {
  unsigned n[2]; /* number of entries */
  unsigned a[2]; /* entries allocated (used only when loading) */
  struct entry *e[2]; /* entries: plain and wildcard */
  unsigned maxlab[2]; /* max level of labels */
  unsigned minlab[2]; /* min level of labels */
  const char *def_rr; /* default A and TXT RRs */
};

/* indexes */
#define EP 0			/* plain entry */
#define EW 1			/* wildcard entry */

static void ds_dnset_free(struct dataset *ds) {
  if (ds) {
    if (ds->e[EP]) free(ds->e[EP]);
    if (ds->e[EW]) free(ds->e[EW]);
    free(ds);
  }
}

static int
ds_dnset_parseline(struct zonedataset *zds, char *s, int lineno) {
  struct dataset *ds = zds->zds_ds;
  unsigned char dn[DNS_MAXDN];
  struct entry *e;
  const char *rr;
  unsigned idx, dnlen, size;
  int not;

  if (*s == ':') {		/* default entry */
    if (!(size = parse_a_txt(s, &rr, def_rr))) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (!(ds->def_rr = mp_dmemdup(&zds->zds_mp, rr, size)))
      return 0;
    return 1;
  }

  /* check negation */
  if (*s == '!') {
    not = 1;
    do ++s;
    while(*s == ' ' || *s == '\t');
  }
  else
    not = 0;

  /* check for wildcard: .xxx or *.xxx */
  if (*s == '.') { idx = EW; ++s; }
  else if (s[0] == '*' && s[1] == '.') { idx = EW; s += 2; }
  else idx = EP;

  /* disallow emptry DN to be listed (i.e. "all"?) */
  if (!(s = parse_dn(s, dn, &dnlen)) || dnlen == 1) {
    dswarn(lineno, "invalid domain name");
    return 1;
  }

  dns_dntol(dn, dn);		/* lowercase */

  if (not)
    rr = NULL;			/* negation entry */
  else {			/* else parse rest */
    skipspace(s);
    if (!*s)			/* use default if none given */
      rr = ds->def_rr;
    else if (!(size = parse_a_txt(s, &rr, ds->def_rr))) {
      dswarn(lineno, "invalid value");
      return 1;
    }
    else if (!(rr = mp_dmemdup(&zds->zds_mp, rr, size)))
      return 0;
  }

  e = ds->e[idx];
  if (ds->n[idx] >= ds->a[idx]) { /* expand array */
    ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    e = trealloc(struct entry, e, ds->a[idx]);
    if (!e) return 0;
    ds->e[idx] = e;
  }

  /* fill up an entry */
  e += ds->n[idx]++;
  if (!(e->lrdn = (unsigned char*)mp_alloc(&zds->zds_mp, dnlen + 1)))
    return 0;
  e->lrdn[0] = (unsigned char)(dnlen - 1);
  dns_dnreverse(dn, e->lrdn + 1, dnlen);
  e->rr = rr;

  /* adjust min/max #labels */
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;

  return 1;
}

static struct dataset *ds_dnset_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds)
    ds->minlab[EP] = ds->minlab[EW] = DNS_MAXDN;
  return ds;
}

static int ds_dnset_load(struct zonedataset *zds, FILE *f) {
  zds->zds_ds->def_rr = def_rr;
  return readdslines(f, zds, ds_dnset_parseline);
}

#define min(a,b) ((a)<(b)?(a):(b))

static int ds_dnset_lt(const struct entry *a, const struct entry *b) {
  /* comparision includes next label length byte (note min()+1) */
  int r = memcmp(a->lrdn + 1, b->lrdn + 1, min(a->lrdn[0], b->lrdn[0]) + 1);
  return
     r < 0 ? 1 :
     r > 0 ? 0 :
     a->rr < b->rr;
}

static int ds_dnset_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 2; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) ds_dnset_lt(a,b)
#   include "qsort.c"

    /* we make all the same DNs point to one string for faster searches */
    { register struct entry *e, *t;
      for(e = ds->e[r], t = e + ds->n[r] - 1; e < t; ++e)
        if (e[0].lrdn[0] == e[1].lrdn[0] &&
            memcmp(e[0].lrdn, e[1].lrdn, e[0].lrdn[0] + 1) == 0)
          e[1].lrdn = e[0].lrdn;
    }
#define dnset_eeq(a,b) a.lrdn == b.lrdn && rrs_equal(a,b)
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

static const struct entry *
ds_dnset_find(const struct entry *e, int n,
              const unsigned char *rdn, unsigned dnlen,
              int *sub) {
  int a = 0, b = n - 1, m, r;

  /* binary search */
  while(a <= b) {
    /* middle entry */
    const struct entry *t = e + (m = (a + b) >> 1);
    /* compare minlen prefixes */
    r = memcmp(t->lrdn + 1, rdn, min(t->lrdn[0], dnlen));
    if (r < 0) a = m + 1;	/* look in last half */
    else if (r > 0) b = m - 1;	/* look in first half */
    /* prefixes match (r == 0) */
    else if (t->lrdn[0] == dnlen) {
      /* found exact match, seek back to
       * first entry with this domain name */
      rdn = (t--)->lrdn;
      while(t > e && t->lrdn == rdn)
        --t;
      return t + 1;
    }
    else if (t->lrdn[0] < dnlen) a = m + 1; /* look in last half */
    else b = m - 1;		/* look in first half */
  }

  /* check if rdn is a subdomain of a listed entry.
   * note that all subdomains are sorted after a superdomain.
   * `a' now points to a place where `rdn' is to be inserted if
   * that where insert operation */
  if (sub /* subdomain checking requested */
      && a < n /* found index is within array, i.e. subdomain possible */
      && dnlen < (e += a)->lrdn[0] /* rdn's len less, subdomain possible */
      && memcmp(rdn, e->lrdn + 1, dnlen) == 0 /* and this is subdomain */
      )
    *sub = 1;

  return NULL;			/* not found */
}

static int
ds_dnset_query(const struct zonedataset *zds, const struct dnsquery *qry,
               struct dnspacket *pkt) {
  const struct dataset *ds = zds->zds_ds;
  const unsigned char *rdn = qry->q_rdn;
  unsigned qlen = qry->q_dnlen - 1;
  unsigned qlab = qry->q_dnlab;
  int sub = 0;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];

  if (!qlab) return 0;		/* do not match empty dn */

  if (qlab > ds->maxlab[EP] 	/* if we have less labels, search unnec. */
      || !(e = ds_dnset_find(ds->e[EP], ds->n[EP], rdn, qlen, &sub))) {

    /* try wildcard */

    /* a funny place.  We will use non-reversed query dn
     * to remove labels at the end of rdn - first label in dn
     * is last label in rdn.  "removing" is done by substracting
     * length of next label from qlen */

    const unsigned char *dn = qry->q_dn;

    /* remove labels until number of labels in query is greather
     * than we have in wildcard array, but remove at least 1 label
     * for wildcard itself. */
    do
      --qlab, qlen -= *dn + 1, dn += *dn + 1;
    while(qlab > ds->maxlab[EW]);

    /* now, lookup every so long rdn in wildcard array */
    for(;;) {

      if (qlab < ds->minlab[EW]) {
        /* oh, number of labels in query become less than
         * minimum we have listed.  Nothing to search anymore */
        if (sub) return 1;	/* if subdomain listed, positive */
        if (qry->q_dnlab > ds->maxlab[EW])
          return 0; /* query can't be superdomain */
        /* if query listed as a wildcard base... */
        if (ds_dnset_find(ds->e[EW], ds->n[EW], rdn, qry->q_dnlen - 1, &sub))
          return 1;
        return sub;		/* ..or it's subdomain */
      }

      /* lookup an entry, do not watch if some subdomain
       * listed (we removed some labels already) */
      if ((e = ds_dnset_find(ds->e[EW], ds->n[EW], rdn, qlen, NULL)))
        break;			/* found, listed */

      /* remove next label at the end of rdn */
      qlen -= *dn + 1;
      dn += *dn + 1;
      --qlab;

    }
    t = ds->e[EW] + ds->n[EW];

  }
  else
    t = ds->e[EP] + ds->n[EP];

  if (!e->rr) return 0;	/* exclusion */
  /*XXX do not return NXDOMAIN if some subdomain exists! */

  rdn = e->lrdn;
  if (qry->q_tflag & NSQUERY_TXT) {
    char dn[DNS_MAXDN];
    dns_dnreverse(e->lrdn + 1, dn, e->lrdn[0] + 1);
    dns_dntop(dn, name, sizeof(name));
  }
  do addrr_a_txt(pkt, qry->q_tflag, e->rr, name, zds);
  while(++e < t && e->lrdn == rdn);

  return 1;
}
