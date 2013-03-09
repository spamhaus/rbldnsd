/* ip6tset dataset type: IP6 half-addresses (/64s),
 * with the same A and TXT values for every individual entry.
 * Exclusions as /64 or /128 are recognized.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"
#include "ip6addr.h"

struct ip6half {
  ip6oct_t a[IP6ADDR_HALF];
};

struct ip6full {
  ip6oct_t a[IP6ADDR_FULL];
};

struct dsdata {
  unsigned a_cnt, e_cnt; /* count */
  unsigned a_alc, e_alc; /* allocated (only for loading) */
  unsigned a_hnt, e_hnt; /* hint: how much to allocate next time */
  struct ip6half *a;	 /* array of entries */
  struct ip6full *e;	 /* array of exclusions */
  const char *def_rr;	 /* default A and TXT RRs */
};

definedstype(ip6tset, DSTF_IP6REV, "(trivial) set of ip6 addresses");

static void ds_ip6tset_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  free(dsd->a); dsd->a = NULL;
  free(dsd->e); dsd->e = NULL;
  dsd->a_alc = dsd->e_alc = 0;
  dsd->a_cnt = dsd->e_cnt = 0;
  dsd->def_rr = NULL;
}

static void ds_ip6tset_start(struct dataset UNUSED *unused_ds) {
}

static int
ds_ip6tset_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  int bits, excl;
  ip6oct_t addr[IP6ADDR_FULL];

  if (*s == ':') {
    if (!dsd->def_rr) {
      unsigned rrl;
      const char *rr;
      if (!(rrl = parse_a_txt(s, &rr, def_rr, dsc)))
        return 1;
      if (!(dsd->def_rr = mp_dmemdup(ds->ds_mp, rr, rrl)))
        return 0;
    }
    return 1;
  }

  excl = *s == '!';
  if (excl) {
    ++s;
    SKIPSPACE(s);
  }

  bits = ip6prefix(s, addr, &s);
  if (bits < 0 ||
      (*s && !ISSPACE(*s) && !ISCOMMENT(*s) && *s != ':')) {
    dswarn(dsc, "invalid address");
    return 1;
  }
  if (bits != (excl ? 128 : 64)) {
    dswarn(dsc, "invalid address for %s (should be %d bits)",
	   excl ? "exclusion" : "regular entry", excl ? 128 : 64);
    return 1;
  }

  if (excl) {
    if (dsd->e_cnt >= dsd->e_alc) {
      struct ip6full *e = dsd->e;
      unsigned alc =
	dsd->e_alc ? dsd->e_alc << 1 :
	dsd->e_hnt ? dsd->e_hnt : 64;
      e = trealloc(struct ip6full, e, alc);
      if (!e)
	return 0;
      dsd->e = e;
      dsd->e_alc = alc;
    }
    memcpy(&(dsd->e[dsd->e_cnt++]), addr, sizeof(*dsd->e));
  }
  else {
    if (dsd->a_cnt >= dsd->a_alc) {
      struct ip6half *a = dsd->a;
      unsigned alc =
	dsd->a_alc ? dsd->a_alc << 1 :
	dsd->a_hnt ? dsd->a_hnt : 64;
      a = trealloc(struct ip6half, a, alc);
      if (!a)
	return 0;
      dsd->a = a;
      dsd->a_alc = alc;
    }
    memcpy(&(dsd->a[dsd->a_cnt++]), addr, sizeof(*dsd->a));
  }

  return 1;
}

static void ds_ip6tset_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  unsigned n;

#define ip6tset_eeq(a,b) memcmp(&a, &b, sizeof(a)) == 0
#define QSORT_LT(a,b) (memcmp(a, b, sizeof(*a)) < 0)

  /* regular entries, ip6halves */
  n = dsd->a_cnt;
  if (!n)
    dsd->a_hnt = 0;
  else {
    struct ip6half *a = dsd->a;

    dsd->a_hnt = dsd->a_alc;
    while((dsd->a_hnt >> 1) >= n)
      dsd->a_hnt >>= 1;

#   define QSORT_TYPE struct ip6half
#   define QSORT_BASE a
#   define QSORT_NELT n
#   include "qsort.c"
#   undef QSORT_NELT
#   undef QSORT_BASE
#   undef QSORT_TYPE

    REMOVE_DUPS(struct ip6half, a, n, ip6tset_eeq);
    SHRINK_ARRAY(struct ip6half, a, n, dsd->a_alc);
    dsd->a = a;
    dsd->a_cnt = n;
  }

  /* exclusions, ip6fulls */
  n = dsd->e_cnt;
  if (!n)
    dsd->e_hnt = 0;
  else {
    struct ip6full *e = dsd->e;

    dsd->e_hnt = dsd->e_alc;
    while((dsd->e_hnt >> 1) >= n)
      dsd->e_hnt >>= 1;

#   define QSORT_TYPE struct ip6full
#   define QSORT_BASE e
#   define QSORT_NELT n
#   include "qsort.c"
#   undef QSORT_NELT
#   undef QSORT_BASE
#   undef QSORT_TYPE

    REMOVE_DUPS(struct ip6full, e, n, ip6tset_eeq);
    SHRINK_ARRAY(struct ip6full, e, n, dsd->a_alc);
    dsd->e = e;
    dsd->e_cnt = n;
  }

  if (!dsd->def_rr) dsd->def_rr = def_rr;
  dsloaded(dsc, "cnt=%u exl=%u", dsd->a_cnt, dsd->e_cnt);
}

static int
ds_ip6tset_find(const struct ip6half *arr, int b, const ip6oct_t *q) {
  int a = 0;
  --b;
  while(a <= b) {
    int m = (a + b) >> 1;
    int r = memcmp(arr[m].a, q, sizeof(*arr));
    if (r == 0) return 1;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_ip6tset_find_excl(const struct ip6full *arr, int b, const ip6oct_t *q) {
  int a = 0;
  --b;
  while(a <= b) {
    int m = (a + b) >> 1;
    int r = memcmp(arr[m].a, q, sizeof(*arr));
    if (r == 0) return 1;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
  return 0;
}

static int
ds_ip6tset_query(const struct dataset *ds, const struct dnsqinfo *qi,
                struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const char *ipsubst;

  if (!qi->qi_ip6valid) return 0;
  check_query_overwrites(qi);

  if (!ds_ip6tset_find(dsd->a, dsd->a_cnt, qi->qi_ip6))
    return 0;
  if (dsd->e_cnt && ds_ip6tset_find_excl(dsd->e, dsd->e_cnt, qi->qi_ip6))
    return 0;

  ipsubst = (qi->qi_tflag & NSQUERY_TXT) ?
    ip6atos(qi->qi_ip6, IP6ADDR_FULL) : NULL;
  addrr_a_txt(pkt, qi->qi_tflag, dsd->def_rr, ipsubst, ds);

  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

static void
ds_ip6tset_dump(const struct dataset *ds,
               const unsigned char UNUSED *unused_odn,
               FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;

  { const struct ip6half *a = dsd->a, *at = a + dsd->a_cnt;
    while(a < at) {
      dump_ip6((a++)->a, 16, dsd->def_rr, ds, f);
    }
  }

  { const struct ip6full *e = dsd->e, *et = e + dsd->e_cnt;
    while(e < et) {
      dump_ip6((e++)->a, 0, NULL, ds, f);
    }
  }

}

#endif
