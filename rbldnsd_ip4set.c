/* ip4set dataset type: IP4 addresses (ranges), with A and TXT
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
  unsigned h[4];	/* hint, how much to allocate next time */
  struct entry *e[4];	/* entries */
  const char *def_rr;	/* default A and TXT RRs */
};

/* indexes */
#define E32 0
#define E24 1
#define E16 2
#define E08 3
/* ..and masks, "network" and "host" parts */
#define M32 0xffffffffu
#define H32 0x00000000u
#define M24 0xffffff00u
#define H24 0x000000ffu
#define M16 0xffff0000u
#define H16 0x0000ffffu
#define M08 0xff000000u
#define H08 0x00ffffffu

definedstype(ip4set, DSTF_IP4REV, "set of (ip4 range, value) pairs");

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
      dsd->a[idx] = dsd->h[idx] ? dsd->h[idx] : 64;
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
ds_ip4set_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  ip4addr_t a, b;
  const char *rr;
  unsigned rrl;

  int not;
  int bits;

  if (*s == ':') {
    if (!(rrl = parse_a_txt(s, &rr, def_rr, dsc)))
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
  if ((bits = ip4range(s, &a, &b, &s)) <= 0 ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  if (accept_in_cidr)
    a &= ip4mask(bits);
  else if (a & ~ip4mask(bits)) {
    dswarn(dsc, "invalid range (non-zero host part)");
    return 1;
  }
  if (dsc->dsc_ip4maxrange && dsc->dsc_ip4maxrange <= (b - a)) {
    dswarn(dsc, "too large range (%u) ignored (%u max)",
           b - a + 1, dsc->dsc_ip4maxrange);
    return 1;
  }
  if (not)
    rr = NULL;
  else {
    SKIPSPACE(s);
    if (!*s || ISCOMMENT(*s))
      rr = dsd->def_rr;
    else if (!(rrl = parse_a_txt(s, &rr, dsd->def_rr, dsc)))
      return 1;
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
    if (b - a == 255u)					\
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

static void ds_ip4set_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned r;
  for(r = 0; r < 4; ++r) {
    if (!dsd->n[r]) {
      dsd->h[r] = 0;
      continue;
    }
    dsd->h[r] = dsd->a[r];
    while((dsd->h[r] >> 1) >= dsd->n[r])
      dsd->h[r] >>= 1;

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
  dsloaded(dsc, "e32/24/16/8=%u/%u/%u/%u",
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
  check_query_overwrites(qi);

#define try(i,mask) \
 (dsd->n[i] && \
  (t = dsd->e[i] + dsd->n[i], \
   e = ds_ip4set_find(dsd->e[i], dsd->n[i], (f = q & mask))) != NULL)

  if (!try(E32, M32) &&
      !try(E24, M24) &&
      !try(E16, M16) &&
      !try(E08, M08))
    return 0;

  if (!e->rr) return 0;		/* exclusion */

  ipsubst = (qi->qi_tflag & NSQUERY_TXT) ? ip4atos(q) : NULL;
  do addrr_a_txt(pkt, qi->qi_tflag, e->rr, ipsubst, ds);
  while(++e < t && e->addr == f);

  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

/* dump the data as master-format file.
 * Having two entries:
 *    127.0.0.0/8  "A"
 *    127.0.0.2    "B"
 * we have to generate the following stuff to make bind return what we need:
 *         *.127 "A"
 *       *.0.127 "A"
 *     *.0.0.127 "A"
 *     2.0.0.127 "B"
 * If we have two (or more) /8 entries, each should be repeated for /16 and /24.
 * The same is when we have /16 and /32 (no /24), or /8 and /24 (no /16).
 *
 * The algorithm is as follows.  We enumerating entries in /8 array
 * (ds_ip4set_dump08()), emitting all "previous" entries in /16 (indicating
 * there's no parent entry), when all entries in lower levels that are
 * covered by our /16 (indicating there IS a parent this time), our own /16
 * group -- all entries with the same address.  ds_ip4set_dump16() accepts
 * 'last' parameter telling it at which address to stop).  ds_ip4set_dump16()
 * does the same with /16s and /24s as ds_ip4set_dump08() does with /8s and
 * /16s.  Similarily, ds_ip4set_dump24() deals with /24s and /32s, but at this
 * point, it should pay attention to the case when there's a /8 but no /16
 * covering the range in question.  Ditto for ds_ip4set_dump32(), which also
 * should handle the case when there's no upper /24 but either /16 or /8 exists.
 */

struct dumpdata {		/* state. */
  const struct entry *e[4];	/* current entry we're looking at in each arr */
  const struct entry *t[4];	/* end pointers for arrays */
  const struct dataset *ds;	/* the dataset in question */
  FILE *f;			/* file to dump data to */
};

/* dump a group of entries with the same IP address.
 * idx shows how many octets we want to print --
 * used only with E08, E16 or E24, not with E32.
 * e is where to start, and t is the end of the array.
 * Returns pointer to the next element after the group.
 */
static const struct entry *
ds_ip4set_dump_group(const struct dumpdata *dd,
                     ip4addr_t saddr, ip4addr_t hmask,
                     const struct entry *e, const struct entry *t) {
  ip4addr_t addr = e->addr;
  do
    dump_ip4range(saddr, saddr | hmask, e->rr, dd->ds, dd->f);
  while(++e < t && e->addr == addr);
  return e;
}

/* dump all /32s up to addr <= last.
 * u08, u16 and u24 is what's on upper levels. */
static void
ds_ip4set_dump32(struct dumpdata *dd, ip4addr_t last,
                 const struct entry *u08, const struct entry *u16,
                 const struct entry *u24) {
  const struct entry *e = dd->e[E32], *t = dd->t[E32];
  ip4addr_t m16 = 1, m24 = 1;
  /* up_rr is true if there's anything non-excluded that is on upper level. */
  int up_rr = (u24 ? u24->rr : u16 ? u16->rr : u08 ? u08->rr : NULL) != NULL;
  while(e < t && e->addr <= last) {
    if (!e->rr && !up_rr) {
      /* skip entry if nothing listed on upper level */
      ++e;
      continue;
    }
    if (!u24 && m24 != (e->addr & M24) && (u08 || u16)) {
      /* if there's no "parent" /24 entry, AND
       * we just advanced to next /24, AND
       * there's something on even-upper levels,
       * we have to repeat something from upper-upper level
       * in mid-level. */
      m24 = e->addr & M24; /* remember parent /24 mask we're in */
      if (!u16 && m16 != (m24 & M16) && u08) {
        /* if there's no parent /16, but there is parent /8:
         * repeat that /8 in current /16, but only once per /16. */
        m16 = m24 & M16;
        ds_ip4set_dump_group(dd, m16, H16, u08, dd->t[E08]);
      }
      /* several cases:
         u16!=0 and isn't exclusion: dump it in upper /24.
         u16!=0 and it IS exclusion: do nothing.
         u08!=0 - dump it.
      */
      if (!u16)			/* u08 is here as per condition above */
        ds_ip4set_dump_group(dd, m24, H24, u08, dd->t[E08]);
      else if (u16->rr)
        ds_ip4set_dump_group(dd, m24, H24, u16, dd->t[E16]);
      /* else nothing: the upper-upper /16 is an exclusion anyway */
    }
    dump_ip4(e->addr, e->rr, dd->ds, dd->f);
    ++e;
  }
  dd->e[E32] = e;
}

/* dump all /24s and lower-levels up to addr <= last.
 * u08 and u16 is what's on upper levels. */
static void
ds_ip4set_dump24(struct dumpdata *dd, ip4addr_t last,
                 const struct entry *u08, const struct entry *u16) {
  const struct entry *e = dd->e[E24], *t = dd->t[E24];
  ip4addr_t m16 = 1, a;
  /* up_rr is true if there's a non-excluded upper-level entry present */
  int up_rr = (u16 ? u16->rr : u08 ? u08->rr : NULL) != NULL;
  while(e < t && (a = e->addr) <= last) {
    if (!e->rr && !up_rr) {
      /* ignore exclusions if there's nothing listed in upper levels */
      ++e;
      continue;
    }
    if (a)
      /* dump all preceeding lower-level entries */
      ds_ip4set_dump32(dd, a - 1, u08, u16, 0);
    /* and this is where the fun is. */
    if (!u16 && m16 != (a & M16) && u08) {
      /* if there's no "parent" /16 entry, AND
       * we just advanced to next /16, AND
       * there's a /8 entry,
       * repeat that /8 in this new /16.
       * This produces *.x.y entry from y/8 and y.x.z/24. */
      m16 = a & M16;
      ds_ip4set_dump_group(dd, m16, H16, u08, dd->t[E08]);
    }
    /* dump all lower-level entries covering by our group */
    ds_ip4set_dump32(dd, a | H24, u08, u16, e);
    /* dump our group */
    e = ds_ip4set_dump_group(dd, a, H24, e, t);
  }
  /* and finally, dump the rest in lower-level groups up to last */
  ds_ip4set_dump32(dd, last, u08, u16, 0);
  dd->e[E24] = e;		/* save loop counter */
}

/* dump all /16s and lower-levels up to addr <= last.
 * u08 is what's on upper levels. */
static void
ds_ip4set_dump16(struct dumpdata *dd, ip4addr_t last,
                 const struct entry *u08) {
  const struct entry *e = dd->e[E16], *t = dd->t[E16];
  while(e < t && e->addr <= last) {
    if (!e->rr && !u08) {
      /* skip exclusion only if there's no upper-level entry */
      ++e;
      continue;
    }
    if (e->addr)
      /* dump all preceeding lower-level entries if any */
      ds_ip4set_dump24(dd, e->addr - 1, u08, 0);
    /* dump all lower-level entries covering by this group */
    ds_ip4set_dump24(dd, e->addr | H16, u08, e);
    /* dump the group itself */
    e = ds_ip4set_dump_group(dd, e->addr, H16, e, t);
  }
  /* and finally, dump the rest in lower levels, up to last */
  ds_ip4set_dump24(dd, last, u08, 0);
  dd->e[E16] = e;		/* update loop variable */
}

/* ok, the simplest case, dump all /8s in turn, unconditionally */
static void
ds_ip4set_dump08(struct dumpdata *dd) {
  const struct entry *e = dd->e[E08], *t = dd->t[E08];
  while(e < t) {
    if (!e->rr) {
      /* just skip all excludes here */
      ++e;
      continue;
    }
    if (e->addr)
      /* dump any preceeding lower-level entries if any */
      ds_ip4set_dump16(dd, e->addr - 1, 0);
    /* dump all entries covered by our group */
    ds_ip4set_dump16(dd, e->addr | H08, e);
    /* dump our own group too */
    e = ds_ip4set_dump_group(dd, e->addr, H08, e, t);
  }
  /* and finally, dump the rest */
  ds_ip4set_dump16(dd, M32, 0);
  dd->e[E08] = e;		/* just in case ;) */
}

static void
ds_ip4set_dump(const struct dataset *ds,
               const unsigned char UNUSED *unused_odn,
               FILE *f) {
  struct dumpdata dd;
  const struct dsdata *dsd = ds->ds_dsd;
  unsigned i;
  for(i = 0; i < 4; ++i)
    dd.t[i] = (dd.e[i] = dsd->e[i]) + dsd->n[i];
  dd.ds = ds;
  dd.f = f;
  ds_ip4set_dump08(&dd);
}
#endif /* NO_MASTER_DUMP */
