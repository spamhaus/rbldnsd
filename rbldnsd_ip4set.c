/* $Id$
 * a simplest zone type: a list of IP addresses with
 * a common text (maybe with a substitution for IP).
 * A list is stored as a sorted array, with binary search --
 * maybe not the most efficient way, but it's the most optimal
 * from the memory requiriments point of view, simple to
 * handle and sufficient enouth (imho)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "dns.h"
#include "qsort.h"

definezonetype(ip4set, NSQUERY_A_TXT, "set of ip4 addresses");

struct zonedata {
  ip4addr_t r_a;	/* A RR */
  char *r_txt;		/* TXT RR */
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated so far (for loading only) */
  int nfile;		/* file #: defaults are loaded from first file only */
  ip4addr_t *e[4];	/* entries */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

static void ip4set_free(struct zonedata *z) {
  if (z) {
    if (z->r_txt) free(z->r_txt);
    if (z->e[E32]) free(z->e[E32]);
    if (z->e[E24]) free(z->e[E24]);
    if (z->e[E16]) free(z->e[E16]);
    if (z->e[E08]) free(z->e[E08]);
    free(z);
  }
}

static int
ip4set_addent(struct zonedata *z, unsigned idx, ip4addr_t a, unsigned count) {
  ip4addr_t *e = z->e[idx];
  ip4addr_t step = 1 << (idx << 3);

  if (z->n[idx] + count > z->a[idx]) {
    do z->a[idx] = z->a[idx] ? z->a[idx] << 1 : 64;
    while(z->n[idx] + count > z->a[idx]);
    e = (ip4addr_t*)erealloc(e, z->a[idx] * sizeof(*e));
    if (!e)
      return 0;
    z->e[idx] = e;
  }

  e += z->n[idx];
  z->n[idx] += count;
  for(; count--; a += step)
    *e++ = a;

  return 1;
}

static int
ip4set_parseline(struct zonedata *z, char *line, int lineno, int llines) {
  char *p;
  ip4addr_t a, b;

  if (!llines && line[0] == ':') {
    /* default entry */
    if (z->nfile > 1)
      return 1;
    if (!addrtxt(line, &a, &p)) {
      zwarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) z->r_a = a;
    if (p && (z->r_txt = estrdup(p)) == NULL)
      return 0;
    return 1;
  }

  /* normal entry */
  if (!ip4parse_range(line, &a, &b, &p) ||
      (*p != '\0' && *p != ' ' && *p != '\t' && *p != '#' && *p != ':')) {
    zwarn(lineno, "invalid entry");
    return 1;
  }

#define fn(idx, start, count) ip4set_addent(z, idx, start, count)
  ip4range_expand(a, b, fn);
}

static int ip4set_load(struct zonedata *z, FILE *f) {
  ++z->nfile;
  return readzlines(f, z, ip4set_parseline);
}

static struct zonedata *ip4set_alloc() {
  struct zonedata *z = (struct zonedata *)emalloc(sizeof(*z));
  if (z) {
    memset(z, 0, sizeof(*z));
    z->r_a = R_A_DEFAULT;
  }
  return z;
}

static ip4addr_t *ip4set_finish1(ip4addr_t *e, unsigned n, unsigned a) {
  if (!n) return NULL;
#define ip4set_cmpent(a,b) (*a < *b ? -1 : *a > *b ? 1 : 0)
  QSORT(ip4addr_t, e, n, ip4set_cmpent);
#define ip4set_eeq(a,b) a == b
  REMOVE_DUPS(e, n, ip4addr_t, ip4set_eeq);
  SHRINK_ARRAY(e, a, n, ip4addr_t);
  return e;
}

static int ip4set_finish(struct zonedata *z) {
  unsigned r;
  for(r = 0; r < 4; ++r)
    z->e[r] = ip4set_finish1(z->e[r], z->n[r], z->a[r]);
  zloaded("e32/24/16/8=%u/%u/%u/%u", 
          z->n[E32], z->n[E24], z->n[E16], z->n[E08]);
  return 1;
}

static int ip4set_find(const ip4addr_t *e, int b, ip4addr_t q) {
  int a = 0, m;
  while(a <= b) {
    if (e[(m = (a + b) >> 1)] == q) return 1;
    else if (e[m] < q) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ip4set_query(const struct zonedata *const z, struct dnspacket *p,
             const unsigned char *const query, unsigned qtyp)
{
  ip4addr_t q;
  if ((q = dntoip4addr(query)) == 0)
    return 0;
#define try(i,mask) \
    (z->n[i] && ip4set_find(z->e[i], z->n[i] - 1, q & mask))
  if (!try(E32, 0xffffffff) && !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) && !try(E08, 0xff000000))
    return 0;
  if (qtyp & NSQUERY_A)
    addrec_a(p, z->r_a);
  if (z->r_txt && qtyp & NSQUERY_TXT)
    addrec_txt(p, z->r_txt, ip4atos(q));
  return 1;
}

