/* $Id$
 * ip4set dataset type: IP4 addresses (ranges), with A and TXT
 * values for every individual entry.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct entry {
  ip4addr_t addr;	/* key: IP address */
  const char *rr;	/* A and TXT RRs */
};

struct dsdata {
  unsigned n[4];	/* counts */
  unsigned a[4];	/* allocated (only for loading) */
  unsigned f[4];	/* how much to allocate next time */
  struct entry *e[4];	/* entries */
  const char *def_rr;	/* default A and TXT RRs */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3

definedstype(ip4set, DSTF_IP4REV, "set of (ip4, value) pairs");

static void ds_ip4set_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  unsigned r;
  for (r = 0; r < 4; ++r) {
    if (!dsd->e[r]) continue;
    free(dsd->e[r]);
    dsd->e[r] = NULL;
    dsd->n[r] = dsd->a[r] = 0;
  }
  dsd->def_rr = NULL;
}

static int
ds_ip4set_addent(struct dsdata *dsd, unsigned idx,
                 ip4addr_t a, unsigned count,
                 const char *rr) {
  struct entry *e = dsd->e[idx];
  ip4addr_t step = 1 << (idx << 3);

  if (dsd->n[idx] + count > dsd->a[idx]) {
    if (!dsd->a[idx])
      dsd->a[idx] = dsd->f[idx] ? dsd->f[idx] : 64;
    while(dsd->n[idx] + count > dsd->a[idx])
      dsd->a[idx] <<= 1;
    e = trealloc(struct entry, e, dsd->a[idx]);
    if (!e)
      return 0;
    dsd->e[idx] = e;
  }

  e += dsd->n[idx];
  dsd->n[idx] += count;
  for(; count--; a += step, ++e) {
    e->addr = a;
    e->rr = rr;
  }

  return 1;
}

static void ds_ip4set_start(struct dataset *ds) {
  ds->ds_dsd->def_rr = def_rr;
}

static int
ds_ip4set_line(struct dataset *ds, char *s, int lineno) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a, b;
  const char *rr;
  unsigned rrl;

  int not;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(lineno, s, &rr, def_rr)))
      return 1;
    if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
    return 1;
  }

  if (*s == '!') {
    not = 1;
    ++s; SKIPSPACE(s);
  }
  else
    not = 0;
  if (!ip4parse_range(s, &a, &b, &s) ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(lineno, "invalid address");
    return 1;
  }
  if (not)
    rr = NULL;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(lineno, s, &rr, dsd->def_rr)))
      dswarn(lineno, "invalid value");
    else if (!(rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
      return 0;
  }

  /*XXX some comments about funny ip4range_expand et al */

#define fn(idx,start,count) ds_ip4set_addent(dsd, idx, start, count, rr)

/* helper macro for ip4range_expand:
 * deal with last octet, shifting a and b when done
 */
#define ip4range_expand_octet(bits)			\
  if ((a | 255u) >= b) {				\
    if ((a ^ b) == 255u)				\
      return fn((bits>>3)+1, a<<bits, 1);		\
    else						\
      return fn(bits>>3, a<<bits, b - a + 1);		\
  }							\
  if (a & 255u) {					\
    if (!fn(bits>>3, a<<bits, 256u - (a & 255u)))	\
      return 0;						\
    a = (a >> 8) + 1;					\
  }							\
  else							\
    a >>= 8;						\
  if ((b & 255u) != 255u) {				\
    if (!fn((bits>>3), (b & ~255u)<<bits, (b&255u)+1))	\
      return 0;						\
    b = (b >> 8) - 1;					\
  }							\
  else							\
    b >>= 8

  ip4range_expand_octet(0);
  ip4range_expand_octet(8);
  ip4range_expand_octet(16);
  return fn(3, a << 24, b - a + 1);

}

static void ds_ip4set_finish(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned r;
  for(r = 0; r < 4; ++r) {
    if (!dsd->n[r]) {
      dsd->f[r] = 0;
      continue;
    }
    dsd->f[r] = dsd->a[r];
    while((dsd->f[r] >> 1) >= dsd->n[r])
      dsd->f[r] >>= 1;

#   define QSORT_TYPE struct entry
#   define QSORT_BASE dsd->e[r]
#   define QSORT_NELT dsd->n[r]
#   define QSORT_LT(a,b) \
       a->addr < b->addr ? 1 : \
       a->addr > b->addr ? 0 : \
       a->rr < b->rr
#   include "qsort.c"

#define ip4set_eeq(a,b) a.addr == b.addr && rrs_equal(a,b)
    REMOVE_DUPS(struct entry, dsd->e[r], dsd->n[r], ip4set_eeq);
    SHRINK_ARRAY(struct entry, dsd->e[r], dsd->n[r], dsd->a[r]);
  }
  dsloaded("e32/24/16/8=%u/%u/%u/%u",
          dsd->n[E32], dsd->n[E24], dsd->n[E16], dsd->n[E08]);
}

static const struct entry *
ds_ip4set_find(const struct entry *e, int b, ip4addr_t q) {
  int a = 0, m;
  --b;
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
ds_ip4set_query(const struct dataset *ds, const struct dnsqinfo *qi,
                struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t q = qi->qi_ip4;
  ip4addr_t f;
  const struct entry *e, *t;
  const char *ipsubst;

  if (!qi->qi_ip4valid) return 0;

#define try(i,mask) \
 (dsd->n[i] && \
  (t = dsd->e[i] + dsd->n[i], \
   e = ds_ip4set_find(dsd->e[i], dsd->n[i], (f = q & mask))) != NULL)

  if (!try(E32, 0xffffffff) &&
      !try(E24, 0xffffff00) &&
      !try(E16, 0xffff0000) &&
      !try(E08, 0xff000000))
    return 0;

  if (!e->rr) return 0;		/* exclusion */

  ipsubst = (qi->qi_tflag & NSQUERY_TXT) ? ip4atos(q) : NULL;
  do addrr_a_txt(pkt, qi->qi_tflag, e->rr, ipsubst, ds);
  while(++e < t && e->addr == f);

  return 1;
}

static void
ds_ip4set_dump(const struct dataset *ds,
               const unsigned char UNUSED *unused_odn,
               FILE *f) {
  unsigned r;
  ip4addr_t a;
  const struct entry *e, *t;
  const struct dsdata *dsd = ds->ds_dsd;
  char name[4*3+3+1];
  for (r = 0; r < 4; ++r) {
    for(e = dsd->e[r], t = e + dsd->n[r]; e < t; ++e) {
      a = e->addr;
      switch(r) {
      case E32:
	sprintf(name, "%u.%u.%u.%u",
		a & 255, (a >> 8) & 255, (a >> 16) & 255, (a >> 24));
	break;
      case E24:
	sprintf(name, "*.%u.%u.%u",
		(a >> 8) & 255, (a >> 16) & 255, (a >> 24));
	break;
      case E16:
	sprintf(name, "*.%u.%u", (a >> 16) & 255, (a >> 24));
	break;
      case E08:
	sprintf(name, "*.%u", (a >> 24));
	break;
      }
      dump_a_txt(name, e->rr, ip4atos(a), ds, f);
    }
  }
}
