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

  if (line[0] == ':') {		/* default entry */
    if (ds->nfile > 1)		/* do nothing if not first file */
      return 1;
    if (ds->defread) {
      dswarn(lineno, "second default entry ignored");
      return 1;
    }
    if (!addrtxt(line, &ds->r_a, &line)) { /* parse it */
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (!ds->r_a) ds->r_a = R_A_DEFAULT;
    if (line && !(ds->r_txt = mp_estrdup(&ds->mp, line)))
      return 0;
    ds->defread = 1;
    return 1;
  }

  /* check for wildcard: .xxx or *.xxx */
  if (*line == '.') { idx = EW; ++line; }
  else if (*line == '*' && line[1] == '.') { idx = EW; line += 2; }
  else idx = EP;

  /* disallow emptry DN to be listed (i.e. "all"?) */
  if (!(line = parse_dn(line, dn, &dnlen)) || dnlen == 1) {
    dswarn(lineno, "invalid domain name");
    return 1;
  }
  dns_dntol(dn, dn);		/* lowercase */

  e = ds->e[idx];
  if (ds->n[idx] >= ds->a[idx]) { /* expand array */
    ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    e = trealloc(struct entry, e, ds->a[idx]);
    if (!e) return 0;
    ds->e[idx] = e;
  }

  /* fill up an entry */
  e += ds->n[idx]++;
  if (!(e->lrdn = (unsigned char*)mp_ealloc(&ds->mp, dnlen + 1))) return 0;
  e->lrdn[0] = (unsigned char)(dnlen - 1);
  dns_dnreverse(dn, e->lrdn + 1, dnlen);

  /* adjust min/max #labels */
  dnlen = dns_dnlabels(dn);
  if (ds->maxlab[idx] < dnlen) ds->maxlab[idx] = dnlen;
  if (ds->minlab[idx] > dnlen) ds->minlab[idx] = dnlen;
 
  return 1;
}

static struct dataset *ds_dnset_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds) {
    ds->r_a = R_A_DEFAULT;
    ds->minlab[EP] = ds->minlab[EW] = DNS_MAXDN;
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
    /* comparision includes next label length byte (note min()+1) */
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
    else if (t->lrdn[0] == dnlen) return t; /* found exact match */
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
ds_dnset_query(const struct dataset *ds,
               const struct dnsquery *query, unsigned qtyp,
               struct dnspacket *packet) {
  const unsigned char *rdn = query->q_rdn;
  unsigned qlen = query->q_dnlen - 1;
  unsigned qlab = query->q_dnlab;
  const struct entry *e;
  int sub = 0;

  if (!qlab) return 0;		/* empty query will never match */

  if (qlab > ds->maxlab[EP] 	/* if we have less labels, search unnec. */
      || !(e = ds_dnset_find(ds->e[EP], ds->n[EP], rdn, qlen, &sub))) {

    /* try wildcard */

    /* a funny place.  We will use non-reversed query dn
     * to remove labels at the end of rdn - first label in dn
     * is last label in rdn.  "removing" is done by substracting
     * length of next label from qlen */

    const unsigned char *dn = query->q_dn;

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
        if (query->q_dnlab > ds->maxlab[EW])
          return 0; /* query can't be superdomain */
        /* if query listed as a wildcard base... */
        if (ds_dnset_find(ds->e[EW], ds->n[EW], rdn, query->q_dnlen - 1, &sub))
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
  }
  if (qtyp & NSQUERY_A) addrec_a(packet, ds->r_a);
  if (ds->r_txt && (qtyp & NSQUERY_TXT)) {
    unsigned char dn[DNS_MAXDN];
    char name[DNS_MAXDOMAIN+1];
    dns_dnreverse(e->lrdn + 1, dn, e->lrdn[0] + 1);
    dns_dntop(dn, name, sizeof(name));
    addrec_txt(packet, ds->r_txt, name);
  }
  return 1;
}
