/* $Id$
 * Zone type which consists of a set of (possible wildcarded)
 * domain names, all sharing the same (A,TXT) result.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definezonetype(dnset, NSQUERY_A_TXT, "set of domain names");

/*
 * We store all domain names in a sorted array, using binary
 * search to find an entry.  There are two similar arrays -
 * for plain entries and for wildcard entries - with all
 * variables indexed by EP and EW.
 */

struct entry {
  const unsigned char *dn; /* mp-allocated */
};

struct zonedata {
  unsigned n[2];	/* number of entries */
  unsigned a[2];	/* entries allocated so far (for loading only) */
  int nfile;		/* file #: we read default only from first file */
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

static void dnset_free(struct zonedata *z) {
  if (z) {
    mp_free(&z->mp);
    if (z->e[EP]) free(z->e[EP]);
    if (z->e[EW]) free(z->e[EW]);
    free(z);
  }
}

static int
dnset_parseline(struct zonedata *z, char *line, int lineno, int llines) {
  char *p;
  unsigned char dn[DNS_MAXDN];
  unsigned idx, labels;
  struct entry *e;

  if (!llines && line[0] == ':') {
    if (z->nfile != 0)
      return 1;
    if (!addrtxt(line, &z->r_a, &p)) {
      zwarn(lineno, "invalid default entry");
      return 1;
    }
    if (!z->r_a) z->r_a = R_A_DEFAULT;
    if (p && !(z->r_txt = mp_estrdup(&z->mp, p)))
      return 0;
    return 1;
  }
  
  for(p = line; *p; ++p)
    if (*p == ' ' || *p == '\t' || *p == '#') break;
  *p = '\0';
  if (*line == '.') { idx = EW; ++line; }
  else if (*line == '*' && line[1] == '.') { idx = EW; line += 2; }
  else idx = EP;
  if (!dns_ptodn(line, dn, DNS_MAXDN)) {
    zwarn(lineno, "invalid domain name");
    return 1;
  }
  dns_dntol(dn, dn);

  e = z->e[idx];
  if (z->n[idx] >= z->a[idx]) {
    z->a[idx] = z->a[idx] ? z->a[idx] << 1 : 64;
    e = (struct entry*)erealloc(e, z->a[idx] * sizeof(*e));
    if (!e) return 0;
    z->e[idx] = e;
  }
  e += z->n[idx]++;
  if (!(e->dn = (const unsigned char*)mp_estrdup(&z->mp, dn))) return 0;
  labels = dns_dnlabels(dn);
  if (z->maxlab[idx] < labels) z->maxlab[idx] = labels;
  if (z->minlab[idx] > labels) z->minlab[idx] = labels;
 
  return 1;
}

static struct zonedata * dnset_alloc() {
  struct zonedata *z = (struct zonedata *)emalloc(sizeof(*z));
  if (z) {
    memset(z, 0, sizeof(*z));
    z->r_a = R_A_DEFAULT;
    z->minlab[EP] = z->minlab[EW] = 256;
  }
  return z;
}

static int
dnset_load(struct zonedata *z, FILE *f) {
  ++z->nfile;
  return readzlines(f, z, dnset_parseline);
}

static int dnset_finish(struct zonedata *z) {
  unsigned r;
  for(r = 0; r < 2; ++r) {
    if (!z->n[r]) continue;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE z->e[r]
#   define QSORT_NELT z->n[r]
#   define QSORT_LT(a,b) strcmp(a->dn, b->dn) < 0
#   include "qsort.c"

#define dnset_eeq(a,b) strcmp(a.dn, b.dn) == 0
    REMOVE_DUPS(struct entry, z->e[r], z->n[r], dnset_eeq);
    SHRINK_ARRAY(struct entry, z->e[r], z->n[r], z->a[r]);
  }
  zloaded("e/w=%u/%u", z->n[EP], z->n[EW]);
  return 1;
}

static int
dnset_find(const struct entry *e, int b, const unsigned char *q) {
  int a = 0, m, r;
  while(a <= b) {
    if (!(r = strcmp(e[(m = (a + b) >> 1)].dn, q))) return 1;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
dnset_query(const struct zonedata *const z, struct dnspacket *p,
            const unsigned char *const query, unsigned labels, unsigned qtyp)
{
  const unsigned char *dn = query;
  if (!labels)
    return 0;
  if (labels > z->maxlab[EP] || labels < z->minlab[EP] ||
      !dnset_find(z->e[EP], z->n[EP] - 1, dn)) {
    /* try wildcard; require at least 1 label on the left */
    do
      --labels, dn += 1 + *dn;
    while(labels > z->maxlab[EW]);
    for(;;) {
      if (labels < z->minlab[EW]) return 0;
      if (dnset_find(z->e[EW], z->n[EW]-1, dn)) break;
      dn += 1 + *dn;
      --labels;
    }
  }
  if (qtyp & NSQUERY_A) addrec_a(p, z->r_a);
  if (z->r_txt && qtyp & NSQUERY_TXT) {
    char name[DNS_MAXDOMAIN+1];
    dns_dntop(query, name, sizeof(name));
    addrec_txt(p, z->r_txt, name);
  }
  return 1;
}

