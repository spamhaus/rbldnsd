/* $Id$
 * Zone type which consists of a set of (possible wildcarded)
 * domain names together with (A,TXT) result for each.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"
#include "qsort.h"

definezonetype(dnvset, NSQUERY_A_TXT, "set of (domain name, value) pairs");

struct entry {
  const unsigned char *dn;	/* key, mp-allocated */
  ip4addr_t r_a;		/* A RR */
  const char *r_txt;		/* TXT RR, mp-allocated */
};

/* zone data and operations is the same as in rbldnsd_dnset,
 * except of instead array of just domain names we store array
 * of structures for each entry.  Also, we allow duplicated entries. */

struct zonedata {
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

static void dnvset_free(struct zonedata *z) {
  if (z) {
    mp_free(&z->mp);
    if (z->e[EP]) free(z->e[EP]);
    if (z->e[EW]) free(z->e[EW]);
    free(z);
  }
}

static int
dnvset_parseline(struct zonedata *z, char *line, int lineno, int llines) {
  char *p;
  ip4addr_t a;
  unsigned char dn[DNS_MAXDN];
  struct entry *e;
  unsigned idx, labels;
  int not;

  if (!llines && line[0] == ':') {
    if (!addrtxt(line, &a, &p)) {
      zwarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) z->r_a = a;
    if (p && !(z->r_txt = mp_edstrdup(&z->mp, p)))
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
  for(p = line; *p; ++p)
    if (*p == ' ' || *p == '\t' || *p == '#') break;
  if (*p) *p++ = '\0';
  if (*line == '.') { idx = EW; ++line; }
  else if (line[0] == '*' && line[1] == '.') { idx = EW; line += 2; }
  else idx = EP;
  if (!dns_ptodn(line, dn, DNS_MAXDN)) {
    zwarn(lineno, "invalid domain name");
    return 1;
  }
  dns_dntol(dn, dn);
  if (not)
    a = 0;
  else {
    if (!addrtxt(p, &a, &p)) {
      zwarn(lineno, "invalid value");
      return 1;
    }
    if (!a)
      a = z->r_a;
  }

  e = z->e[idx];
  if (z->n[idx] >= z->a[idx]) {
    z->a[idx] = z->a[idx] ? z->a[idx] << 1 : 64;
    e = (struct entry *)erealloc(e, z->a[idx] * sizeof(*e));
    if (!e) return 0;
    z->e[idx] = e;
  }
  e += z->n[idx]++;
  e->r_a = a;
  if (not) e->r_txt = NULL;
  else if (!p) e->r_txt = z->r_txt;
  else if (!(e->r_txt = mp_edstrdup(&z->mp, p))) return 0;
  if (!(e->dn = (const unsigned char*)mp_estrdup(&z->mp, dn)))
    return 0;
  labels = dns_dnlabels(dn);
  if (z->maxlab[idx] < labels) z->maxlab[idx] = labels;
  if (z->minlab[idx] > labels) z->minlab[idx] = labels;

  return 1;
}

static struct zonedata *dnvset_alloc() {
  struct zonedata *z = (struct zonedata *)emalloc(sizeof(*z));
  if (z) {
    memset(z, 0, sizeof(*z));
    z->minlab[EP] = z->minlab[EW] = 255;
  }
  return z;
}

static int
dnvset_load(struct zonedata *z, FILE *f) {
  z->r_a = R_A_DEFAULT;
  z->r_txt = NULL;
  return readzlines(f, z, dnvset_parseline);
}

static inline int dnvset_cmpent(const struct entry *a, const struct entry *b) {
  int r = strcmp(a->dn, b->dn);
  if (r) return r;
  if (a->r_a < b->r_a) return -1;
  if (a->r_a > b->r_a) return 1;
  return 0;
}

static struct entry *dnvset_finish1(struct entry *e, unsigned n, unsigned a) {
  if (!n) return NULL;
  QSORT(struct entry, e, n, dnvset_cmpent);
  /* we make all the same DNs point to one string for faster searches */
  { register struct entry *p, *t;
    for(p = e, t = e + n - 1; p < t; ++p)
      if (p[0].dn != p[1].dn && strcmp(p[0].dn, p[1].dn) == 0)
        p[1].dn = p[0].dn;
  }
#define dnvset_eeq(a,b) a.dn == b.dn && rrs_equal(a,b)
  REMOVE_DUPS(e, n, struct entry, dnvset_eeq);
  SHRINK_ARRAY(e, a, n, struct entry);
  return e;
}

static int dnvset_finish(struct zonedata *z) {
  unsigned r;
  for(r = 0; r < 2; ++r)
    z->e[r] = dnvset_finish1(z->e[r], z->n[r], z->a[r]);
  zloaded("e/w=%u/%u", z->n[EP], z->n[EW]);
  return 1;
}

static const struct entry *
dnvset_find(const struct entry *e, int b, const unsigned char *q) {
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
dnvset_query(const struct zonedata *const z, struct dnspacket *p,
             const unsigned char *const query, unsigned qtyp)
{
  const unsigned char *dn = query;
  unsigned labels;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];
  if ((labels = dns_dnlabels(dn)) == 0)
    return 0;
  if (labels > z->maxlab[EP] || labels < z->minlab[EP] ||
      !(e = dnvset_find(z->e[EP], z->n[EP] - 1, dn))) {
    /* try wildcard; require at least 1 label on the left */
    do
      --labels, dn += 1 + *dn;
    while(labels > z->maxlab[EW]);
    for(;;) {
      if (labels < z->minlab[EW]) return 0;
      if ((e = dnvset_find(z->e[EW], z->n[EW]-1, dn)) != NULL) break;
      dn += 1 + *dn;
      --labels;
    }
    t = z->e[EW] + z->n[EW];
  }
  else
    t = z->e[EP] + z->n[EP];

  if (!e->r_a) return 0;

  dn = e->dn;
  if (qtyp & NSQUERY_TXT)
    dns_dntop(query, name, sizeof(name));
  do {
    if (qtyp & NSQUERY_A)
      addrec_a(p, e->r_a);
    if (z->r_txt && qtyp & NSQUERY_TXT)
      addrec_txt(p, e->r_txt, name);
  } while(++e < t && e->dn == dn);

  return 1;
}
