/* $Id$
 * ip4vset zonetype: IP4 addresses (ranges), with A and TXT
 * values for every individual entry.  More flexible than
 * ip4set but requires more memory.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"
#include "qsort.h"

definezonetype(ip4vset, NSQUERY_A_TXT, "set of (ip4, value) pairs");

struct entry {
  ip4addr_t addr;	/* key */
  ip4addr_t r_a;	/* result: addr */
  const char *r_txt;	/* result: txt (mempool) */
};

struct zonedata {
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated (only for loading) */
  struct entry *e[4];	/* entries */
  struct mempool mp;	/* mempool for TXT RRs */
  ip4addr_t r_a;	/* default A RR */
  const char *r_txt;	/* default txt (mempool) */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

static void ip4vset_free(struct zonedata *z) {
  if (z) {
    mp_free(&z->mp);
    if (z->e[E32]) free(z->e[E32]);
    if (z->e[E24]) free(z->e[E24]);
    if (z->e[E16]) free(z->e[E16]);
    if (z->e[E08]) free(z->e[E08]);
    free(z);
  }
}

static int
ip4vset_addent(struct zonedata *z, unsigned idx, ip4addr_t a, unsigned count,
               ip4addr_t r_a, const char *r_txt) {
  struct entry *e = z->e[idx];
  ip4addr_t step = 1 << (idx << 3);

  if (z->n[idx] + count > z->a[idx]) {
    do z->a[idx] = z->a[idx] ? z->a[idx] << 1 : 64;
    while(z->n[idx] + count > z->a[idx]);
    e = (struct entry*)erealloc(e, z->a[idx] * sizeof(*e));
    if (!e)
      return 0;
    z->e[idx] = e;
  }

  e += z->n[idx];
  z->n[idx] += count;
  for(; count--; a += step, ++e) {
    e->addr = a;
    e->r_a = r_a;
    e->r_txt = r_txt;
  }

  return 1;
}

static int
ip4vset_parseline(struct zonedata *z, char *line, int lineno, int llines) {
  ip4addr_t a, b;
  char *p;
  ip4addr_t r_a;
  const char *r_txt;
  int not;

  if (!llines && line[0] == ':') {
    if (!addrtxt(line, &a, &p)) {
      zwarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) z->r_a = a;
    if (p && (z->r_txt = mp_edstrdup(&z->mp, p)) == NULL)
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
  if (!ip4parse_range(line, &a, &b, &p) ||
      (*p != '\0' && *p != ' ' && *p != '\t' && *p != '#' && *p != ':')) {
    zwarn(lineno, "invalid address");
    return 1;
  }
  if (not)
    r_a = 0;
  else {
    if (!addrtxt(p, &r_a, &p)) {
      zwarn(lineno, "invalid value");
      return 1;
    }
    if (!r_a)
      r_a = z->r_a;
  }

  if (not) r_txt = NULL;
  else if (!p) r_txt = z->r_txt;
  else if (!(r_txt = mp_edstrdup(&z->mp, p))) return 0;

#define fn(idx,start,count) ip4vset_addent(z, idx, start, count, r_a, r_txt)
  ip4range_expand(a, b, fn);
}

static int ip4vset_load(struct zonedata *z, FILE *f) {
  z->r_a = R_A_DEFAULT;
  z->r_txt = NULL;
  return readzlines(f, z, ip4vset_parseline);
}

static struct zonedata *ip4vset_alloc() {
  struct zonedata *z = (struct zonedata *)emalloc(sizeof(*z));
  if (z)
    memset(z, 0, sizeof(*z));
  return z;
}

static struct entry *ip4vset_finish1(struct entry *e, unsigned n, unsigned a) {
  if (!n) return NULL;
#define ip4vset_cmpent(a,b) \
    a->addr < b->addr ? -1 : a->addr > b->addr ? 1 : \
      a->r_a < b->r_a ? -1 : a->r_a > b->r_a ? 1 : \
        0
  QSORT(struct entry, e, n, ip4vset_cmpent);
#define ip4vset_eeq(a,b) a.addr == b.addr && rrs_equal(a,b)
  REMOVE_DUPS(e, n, struct entry, ip4vset_eeq);
  SHRINK_ARRAY(e, a, n, struct entry);
  return e;
}

static int ip4vset_finish(struct zonedata *z) {
  unsigned r;
  for(r = 0; r < 4; ++r)
    z->e[r] = ip4vset_finish1(z->e[r], z->n[r], z->a[r]);
  zloaded("e32/24/16/8=%u/%u/%u/%u",
          z->n[E32], z->n[E24], z->n[E16], z->n[E08]);
  return 1;
}

static const struct entry *
ip4vset_find(const struct entry *e, int b, ip4addr_t q) {
  int a = 0, m;
  while(a <= b) {
    if (e[(m = (a + b) >> 1)].addr == q) {
      const struct entry *p = e + m - 1;
      while(p >= e && p->addr == q)
        --p;
      return p + 1;
    }
    else if (e[m].addr < q) a = m + 1;
    else b = m - 1;
  }
  return NULL;
}

static int
ip4vset_query(const struct zonedata *const z, struct dnspacket *p,
              const unsigned char *const query, unsigned qtyp)
{
  ip4addr_t q, f;
  const struct entry *e, *t;
  const char *ipsubst;

  if (!(q = dntoip4addr(query)))
    return 0;

#define try(i,mask) \
 (z->n[i] && \
  (t = z->e[i] + z->n[i], \
   e = ip4vset_find(z->e[i], z->n[i] - 1, (f = q & mask))) != NULL)

  if (!try(E32, 0xffffffff) &&
      !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) &&
      !try(E08, 0xff000000))
    return 0;

  if (!e->r_a) return 0;

  ipsubst = (qtyp & NSQUERY_TXT) ? ip4atos(q) : NULL;
  do {
    if (qtyp & NSQUERY_A)
      addrec_a(p, e->r_a);
    if (e->r_txt && qtyp & NSQUERY_TXT)
      addrec_txt(p, e->r_txt, ipsubst);
  } while(++e < t && e->addr == f);

  return 1;
}
