/* $Id$
 * Dataset type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct entry {
  unsigned char *ldn;	/* DN key, mp-allocated, length byte first */
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

definedstype(dnset, 0, "set of (domain name, value) pairs");

static void ds_dnset_reset(struct dataset *ds) {
  if (ds->e[EP]) free(ds->e[EP]);
  if (ds->e[EW]) free(ds->e[EW]);
  memset(ds, 0, sizeof(*ds));
  ds->minlab[EP] = ds->minlab[EW] = DNS_MAXDN;
}

static void ds_dnset_start(struct dataset *ds) {
  ds->def_rr = def_rr;
}

static int
ds_dnset_line(struct zonedataset *zds, char *s, int lineno) {
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
    ++s; SKIPSPACE(s);
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
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))	/* use default if none given */
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
  if (!(e->ldn = (unsigned char*)mp_alloc(&zds->zds_mp, dnlen + 1)))
    return 0;
  e->ldn[0] = (unsigned char)(dnlen);
  memcpy(e->ldn + 1, dn, dnlen);
  e->rr = rr;

  /* adjust min/max #labels */
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;

  return 1;
}

#define min(a,b) ((a)<(b)?(a):(b))

static int ds_dnset_lt(const struct entry *a, const struct entry *b) {
  int r = memcmp(a->ldn + 1, b->ldn + 1, min(a->ldn[0], b->ldn[0]));
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
        if (e[0].ldn[0] == e[1].ldn[0] &&
            memcmp(e[0].ldn, e[1].ldn, e[0].ldn[0]) == 0)
          e[1].ldn = e[0].ldn;
    }
#define dnset_eeq(a,b) a.ldn == b.ldn && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, ds->e[r], ds->n[r], dnset_eeq);
    SHRINK_ARRAY(struct entry, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e/w=%u/%u", ds->n[EP], ds->n[EW]);
  return 1;
}

static const struct entry *
ds_dnset_find(const struct entry *e, int n,
              const unsigned char *dn, unsigned dnlen) {
  int a = 0, b = n - 1, m, r;

  /* binary search */
  while(a <= b) {
    /* middle entry */
    const struct entry *t = e + (m = (a + b) >> 1);
    /* compare minlen prefixes */
    r = memcmp(t->ldn + 1, dn, min(t->ldn[0], dnlen));
    if (r < 0) a = m + 1;	/* look in last half */
    else if (r > 0) b = m - 1;	/* look in first half */
    else {
      /* found exact match, seek back to
       * first entry with this domain name */
      dn = (t--)->ldn;
      while(t > e && t->ldn == dn)
        --t;
      return t + 1;
    }
  }

  return NULL;			/* not found */
}

static int
ds_dnset_query(const struct zonedataset *zds, const struct dnsquery *qry,
               struct dnspacket *pkt) {
  const struct dataset *ds = zds->zds_ds;
  const unsigned char *dn = qry->q_dn;
  unsigned qlen = qry->q_dnlen;
  unsigned qlab = qry->q_dnlab;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];

  if (!qlab) return 0;		/* do not match empty dn */

  if (qlab > ds->maxlab[EP] 	/* if we have less labels, search unnec. */
      || qlab < ds->minlab[EP]	/* ditto for more */
      || !(e = ds_dnset_find(ds->e[EP], ds->n[EP], dn, qlen))) {

    /* try wildcard */

    /* remove labels until number of labels in query is greather
     * than we have in wildcard array, but remove at least 1 label
     * for wildcard itself. */
    do
      --qlab, qlen -= *dn + 1, dn += *dn + 1;
    while(qlab > ds->maxlab[EW]);

    /* now, lookup every so long dn in wildcard array */
    for(;;) {

      if (qlab < ds->minlab[EW])
        /* oh, number of labels in query become less than
         * minimum we have listed.  Nothing to search anymore */
        return 0;

      if ((e = ds_dnset_find(ds->e[EW], ds->n[EW], dn, qlen)))
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

  dn = e->ldn;
  if (qry->q_tflag & NSQUERY_TXT)
    dns_dntop(e->ldn + 1, name, sizeof(name));
  do addrr_a_txt(pkt, qry->q_tflag, e->rr, name, zds);
  while(++e < t && e->ldn == dn);

  return 1;
}

static void ds_dnset_dump(const struct zonedataset *zds, FILE *f) {
  const struct dataset *ds = zds->zds_ds;
  const struct entry *e, *t;
  unsigned char name[DNS_MAXDOMAIN+4];
  for (e = ds->e[EP], t = e + ds->n[EP]; e < t; ++e) {
    dns_dntop(e->ldn + 1, name, sizeof(name));
    dump_a_txt(name, e->rr, name, zds, f);
  }
  name[0] = '*'; name[1] = '.';
  for (e = ds->e[EW], t = e + ds->n[EW]; e < t; ++e) {
    dns_dntop(e->ldn + 1, name + 2, sizeof(name) - 2);
    dump_a_txt(name, e->rr, name + 2, zds, f);
  }
}
