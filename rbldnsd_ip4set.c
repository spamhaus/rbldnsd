/* $Id$
 * a simplest dataset type: a list of IP addresses with
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

definedstype(ip4set, DSTF_IP4REV, "set of ip4 addresses");

struct dataset {
  ip4addr_t r_a;	/* A RR */
  char *r_txt;		/* TXT RR */
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated so far (for loading only) */
  int nfile;		/* file #: defaults are loaded from first file only */
  int defread;		/* defaults has been read */
  ip4addr_t *e[4];	/* entries */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

static void ds_ip4set_free(struct dataset *ds) {
  if (ds) {
    if (ds->r_txt) free(ds->r_txt);
    if (ds->e[E32]) free(ds->e[E32]);
    if (ds->e[E24]) free(ds->e[E24]);
    if (ds->e[E16]) free(ds->e[E16]);
    if (ds->e[E08]) free(ds->e[E08]);
    free(ds);
  }
}

static int
ds_ip4set_addent(struct dataset *ds, unsigned idx, ip4addr_t a, unsigned count)
{
  ip4addr_t *e = ds->e[idx];
  ip4addr_t step = 1 << (idx << 3);

  if (ds->n[idx] + count > ds->a[idx]) {
    do ds->a[idx] = ds->a[idx] ? ds->a[idx] << 1 : 64;
    while(ds->n[idx] + count > ds->a[idx]);
    e = trealloc(ip4addr_t, e, ds->a[idx]);
    if (!e)
      return 0;
    ds->e[idx] = e;
  }

  e += ds->n[idx];
  ds->n[idx] += count;
  for(; count--; a += step)
    *e++ = a;

  return 1;
}

static int
ds_ip4set_parseline(struct dataset *ds, char *line, int lineno) {
  char *p;
  ip4addr_t a, b;

  if (line[0] == ':') { /* defaults */
    if (ds->nfile > 1)
      return 1;
    if (ds->defread) {
      dswarn(lineno, "second default entry ignored");
      return 1;
    }
    if (!addrtxt(line, &a, &p)) {
      dswarn(lineno, "invalid default entry");
      return 1;
    }
    if (a) ds->r_a = a;
    if (p && (ds->r_txt = estrdup(p)) == NULL)
      return 0;
    ds->defread = 1;
    return 1;
  }

  /* normal entry */
  if (!ip4parse_range(line, &a, &b, &p) ||
      (*p != '\0' && *p != ' ' && *p != '\t' && *p != '#' && *p != ':')) {
    dswarn(lineno, "invalid entry");
    return 1;
  }

#define fn(idx, start, count) ds_ip4set_addent(ds, idx, start, count)
  ip4range_expand(a, b, fn);
}

static int ds_ip4set_load(struct zonedataset *zds, FILE *f) {
  ++zds->zds_ds->nfile;
  return readdslines(f, zds, ds_ip4set_parseline);
}

static struct dataset *ds_ip4set_alloc() {
  struct dataset *ds = tzalloc(struct dataset);
  if (ds)
    ds->r_a = R_A_DEFAULT;
  return ds;
}

static int ds_ip4set_finish(struct dataset *ds) {
  unsigned r;
  for(r = 0; r < 4; ++r) {
    if (!ds->n[r]) continue;

#   define QSORT_TYPE ip4addr_t
#   define QSORT_BASE ds->e[r]
#   define QSORT_NELT ds->n[r]
#   define QSORT_LT(a,b) *a < *b
#   include "qsort.c"

#define ip4set_eeq(a,b) a == b
    REMOVE_DUPS(ip4addr_t, ds->e[r], ds->n[r], ip4set_eeq);
    SHRINK_ARRAY(ip4addr_t, ds->e[r], ds->n[r], ds->a[r]);
  }
  dsloaded("e32/24/16/8=%u/%u/%u/%u", 
          ds->n[E32], ds->n[E24], ds->n[E16], ds->n[E08]);
  return 1;
}

static int ds_ip4set_find(const ip4addr_t *e, int b, ip4addr_t q) {
  int a = 0, m;
  while(a <= b) {
    if (e[(m = (a + b) >> 1)] == q) return 1;
    else if (e[m] < q) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_ip4set_find_masked(const ip4addr_t *e, int b, ip4addr_t q, ip4addr_t mask) {
  int a = 0, m;
  while(a <= b) {
    if ((e[(m = (a + b) >> 1)] & mask) == q) return 1;
    else if ((e[m] & mask) < q) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_ip4set_query(const struct dataset *ds, const struct dnsquery *query,
                struct dnspacket *packet) {
  ip4addr_t q = query->q_ip4;

  if (query->q_ip4oct < 4) {
    ip4addr_t f;
    unsigned n, l;

    if (!(l = query->q_ip4oct)) return 0;

    /* we can't return NXDOMAIN for 3.2.1.bl.example.com -
     * e.g. if 4.3.2.1.bl.example.com exists */
    f = ip4mask(l * 8);
    n = E32;
    do
      if (ds_ip4set_find_masked(ds->e[n], ds->n[n] - 1, q, f))
        return 1;
    while (++n < 4 - l);
    while(n <= E08) {
      q &= f;
      if (ds_ip4set_find(ds->e[n], ds->n[n] - 1, q)) return 1;
      f <<= 8;
      ++n;
    }
    return 0;
  }

  /* valid 4-octets IP */

#define try(i,mask) \
    (ds->n[i] && ds_ip4set_find(ds->e[i], ds->n[i] - 1, q & mask))
  if (!try(E32, 0xffffffff) && !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) && !try(E08, 0xff000000))
    return 0;
  if (query->q_type & NSQUERY_A)
    addrec_a(packet, ds->r_a);
  if (ds->r_txt && (query->q_type & NSQUERY_TXT))
    addrec_txt(packet, ds->r_txt, ip4atos(q));
  return 1;
}
