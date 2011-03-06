/* generic dataset, simplified bind format.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct entry {
  const unsigned char *ldn;	/* DN, first byte is length, w/o EON */
  unsigned dtyp;		/* data (query) type (NSQUERY_XX) */
  unsigned ttl;			/* time-to-live */
  unsigned char *data;	/* data, mp-allocated (size depends on dtyp) */
};

struct dsdata {
  unsigned n;		/* number of entries */
  unsigned a;		/* entries allocated (only when loading) */
  struct entry *e;	/* entries */
  unsigned maxlab;	/* max level of labels */
  unsigned minlab;	/* min level of labels */
};

definedstype(generic, 0, "generic simplified bind-format");

static void ds_generic_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  if (dsd->e) free(dsd->e);
  memset(dsd, 0, sizeof(*dsd));
  dsd->minlab = DNS_MAXDN;
}

static void ds_generic_start(struct dataset UNUSED *unused_ds) {
}

static int
ds_generic_parseany(struct dataset *ds, char *s, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  struct entry *e;
  char *t;
  unsigned dtyp, dsiz, dnlab;
  unsigned char data[DNS_MAXDN*2+20];
  unsigned char *dp;

  /* allocate new entry */
  e = dsd->e;
  if (dsd->n >= dsd->a) {
    dsd->a = dsd->a ? dsd->a << 1 : 8;
    e = trealloc(struct entry, e, dsd->a);
    if (!e) return 0;
    dsd->e = e;
  }
  e += dsd->n;

  /* dn */
  if (s[0] == '@' && ISSPACE(s[1])) {
    data[1] = '\0';
    dsiz = 1;
    s += 2;
    SKIPSPACE(s);
  }
  else if (!(s = parse_dn(s, data + 1, &dsiz)) || dsiz == 1)
    return -1;
  else
    dns_dntol(data + 1, data + 1);
  dnlab = dns_dnlabels(data + 1);
  data[0] = (unsigned char)(dsiz - 1);
  if (!(e->ldn = mp_dmemdup(ds->ds_mp, data, dsiz)))
    return 0;

  SKIPSPACE(s);

  if (*s >= '0' && *s <= '9') { /* ttl */
    if (!(s = parse_ttl(s, &e->ttl, ds->ds_ttl))) return 0;
    SKIPSPACE(s);
  }
  else
    e->ttl = ds->ds_ttl;

  dp = data;

  /* type */
  if ((s[0] == 'i' || s[0] == 'I') &&
      (s[1] == 'n' || s[1] == 'N') &&
      ISSPACE(s[2])) { /* skip IN class name */
    s += 2;
    SKIPSPACE(s);
  }
  t = s;
  while(!ISSPACE(*s))
    if (!*s) return -1;
    else { *s = dns_dnlc(*s); ++s; }
  *s++ = '\0';
  SKIPSPACE(s);

  if (strcmp(t, "a") == 0) {
    ip4addr_t a;
    dtyp = NSQUERY_A;
    if (ip4addr(s, &a, &s) <= 0) return -1;
    PACK32(dp, a);
    dsiz = 4;
  }

  else if (strcmp(t, "txt") == 0) {
    dtyp = NSQUERY_TXT;
    dsiz = strlen(s);
    if (dsiz >= 2 && s[0] == '"' && s[dsiz-1] == '"')
      ++s, dsiz -= 2;
    if (dsiz > 255) {
      dswarn(dsc, "TXT RR truncated to 255 bytes");
      dsiz = 255;
    }
    dp[0] = (char)dsiz;
    memcpy(dp+1, s, dsiz);
    dsiz += 1;
  }

  else if (strcmp(t, "mx") == 0) {
    dtyp = NSQUERY_MX;
    if (!(s = parse_uint32_nb(s, dp)) || dp[0] || dp[1]) return -1;
    dp[1] = dp[2]; dp[2] = dp[3];
    if (!(s = parse_dn(s, dp + 3, &dsiz))) return 0;
    if (*s) return 0;
    dp[0] = (unsigned char)dsiz;
    dsiz += 3;
  }

  else
    return -1;

  e->dtyp = dtyp;
  dsiz += 4;
  if (!(e->data = mp_alloc(ds->ds_mp, dsiz, 0)))
    return 0;
  memcpy(e->data, data, dsiz);

  ++dsd->n;
  if (dsd->maxlab < dnlab) dsd->maxlab = dnlab;
  if (dsd->minlab > dnlab) dsd->minlab = dnlab;

  return 1;
}

static int
ds_generic_line(struct dataset *ds, char *s, struct dsctx *dsc) {
  int r = ds_generic_parseany(ds, s, dsc);
  if (r < 0) {
    dswarn(dsc, "invalid/unrecognized entry");
    return 1;
  }
  else if (!r)
    return 0;
  else
    return 1;
}

#define min(a,b) ((a)<(b)?(a):(b))

/* comparision of first MINlen bytes of two DNs is sufficient
 * due to the nature of domain name representation */

static int ds_generic_lt(const struct entry *a, const struct entry *b) {
  int r = memcmp(a->ldn, b->ldn, a->ldn[0] + 1);
  if (r < 0) return 1;
  else if (r > 0) return 0;
  else return a->dtyp < b->dtyp;
}

static void ds_generic_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  if (dsd->n) {

#   define QSORT_TYPE struct entry
#   define QSORT_BASE dsd->e
#   define QSORT_NELT dsd->n
#   define QSORT_LT(a,b) ds_generic_lt(a,b)
#   include "qsort.c"

    /* collect all equal DNs to point to the same place */
    { struct entry *e, *t;
      for(e = dsd->e, t = e + dsd->n - 1; e < t; ++e)
        if (memcmp(e[0].ldn, e[1].ldn, e[0].ldn[0] + 1) == 0)
          e[1].ldn = e[0].ldn;
    }
    SHRINK_ARRAY(struct entry, dsd->e, dsd->n, dsd->a);
  }
  dsloaded(dsc, "e=%u", dsd->n);
}

static const struct entry *
ds_generic_find(const struct entry *e, int b, const unsigned char *dn, unsigned qlen0) {
  int a = 0, m, r;
  const struct entry *t;
  --b;
  for(;;) {
    if (a > b) return 0;
    t = e + (m = (a + b) >> 1);
    if (t->ldn[0] < qlen0) a = m + 1;
    else if (t->ldn[0] > qlen0) b = m - 1;
    else if (!(r = memcmp(t->ldn + 1, dn, qlen0))) return t;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }
}

static void
ds_generic_add_rr(struct dnspacket *pkt, const struct entry *e) {
  const unsigned char *d = e->data;
  switch(e->dtyp) {
  case NSQUERY_A:
    addrr_any(pkt, DNS_T_A, d, 4, e->ttl);
    break;
  case NSQUERY_TXT:
    addrr_any(pkt, DNS_T_TXT, d, (unsigned)(d[0]) + 1, e->ttl);
    break;
  case NSQUERY_MX:
    addrr_any(pkt, DNS_T_MX, d + 1, (unsigned)(d[0]) + 2, e->ttl);
    break;
  }
}

static void
ds_generic_add_rrs(struct dnspacket *pkt, const struct entry *e, const struct entry *l) {
  /* this routine should randomize order of the RRs when placing them
   * into the resulting packet.  Currently, we use plain "dumb" round-robin,
   * that is, given N RRs, we chose some M in between, based on a single
   * sequence nn, and will return M..N-1 records first, and 0..M-1 records
   * second.  Dumb, dumb, I know, but this is very simple to implement!.. ;) */
  static unsigned nn;
  const struct entry *m = (l - e > 1) ? e + nn++ % (l - e) : e;
  const struct entry *t;
  for(t = m; t < l; ++t) ds_generic_add_rr(pkt, t);
  for(t = e; t < m; ++t) ds_generic_add_rr(pkt, t);
}

static int
ds_generic_query(const struct dataset *ds, const struct dnsqinfo *qi,
                 struct dnspacket *pkt) {
  const struct dsdata *dsd = ds->ds_dsd;
  const unsigned char *dn = qi->qi_dn;
  const struct entry *e, *t, *l;
  unsigned qt = qi->qi_tflag;

  if (qi->qi_dnlab > dsd->maxlab || qi->qi_dnlab < dsd->minlab)
    return 0;

  e = dsd->e;
  t = ds_generic_find(e, dsd->n, qi->qi_dn, qi->qi_dnlen0);
  if (!t)
    return 0;

  /* find first and last entries with the DN and qtype in question */
  dn = t->ldn;
  if (qt == NSQUERY_ANY) {
    /* ANY query, we want all records regardless of type;
     * but "randomize" each type anyway */
    do --t;
    while(t >= e && t->ldn == dn);
    l = e + dsd->n;
    e = t + 1;
    t = e + 1;
    qt = e->dtyp;
    for(;;) {
      if (t >= l || t->ldn != dn) {
        ds_generic_add_rrs(pkt, e, t);
        break;
      }
      else if (t->dtyp != qt) {
	qt = t->dtyp;
        ds_generic_add_rrs(pkt, e, t);
        e = t;
      }
      ++t;
    }
  }
  else if (qt == NSQUERY_OTHER)
    return 1; /* we have nothing of this type */
  else if (t->dtyp > qt) { /* search backward */
    do if (--t < e || t->ldn != dn || t->dtyp < qt) return 1;
    while (t->dtyp > qt);
    l = t + 1;
    do --t;
    while(t >= e && t->ldn == dn && t->dtyp == qt);
    ds_generic_add_rrs(pkt, t + 1, l);
  }
  else if (t->dtyp < qt) { /* search forward */
    l = e + dsd->n;
    do if (++t >= l || t->ldn != dn || t->dtyp > qt) return 1;
    while(t->dtyp < qt);
    e = t;
    do ++t;
    while(t < l && t->ldn == dn && t->dtyp == qt);
    ds_generic_add_rrs(pkt, e, t);
  }
  else { /* we're here, find boundaries */
    l = t;
    do --t;
    while(t >= e && t->ldn == dn && t->dtyp == qt);
    e = t + 1;
    t = dsd->e + dsd->n;
    do ++l;
    while(l < t && l->ldn == dn && l->dtyp == qt);
    ds_generic_add_rrs(pkt, e, l);
  }
  return NSQUERY_FOUND;
}

#ifndef NO_MASTER_DUMP

static void
ds_generic_dump(const struct dataset *ds,
                const unsigned char UNUSED *unused_odn,
                FILE *f) {
  const struct dsdata *dsd = ds->ds_dsd;
  const struct entry *e, *t;
  unsigned char dn[DNS_MAXDN];
  char name[DNS_MAXDOMAIN+1];
  const unsigned char *ldn = NULL;
  const unsigned char *d;

  for (e = dsd->e, t = e + dsd->n; e < t; ++e) {
    if (ldn != e->ldn) {
      ldn = e->ldn;
      if (ldn[0] > 1) {
        memcpy(dn, ldn + 1, ldn[0]);
	dn[ldn[0]] = '\0';
        dns_dntop(dn, name, sizeof(name));
      }
      else
        strcpy(name, "@");
    }
    else
      name[0] = '\0';
    fprintf(f, "%s\t%u\t", name, e->ttl);
    d = e->data;
    switch(e->dtyp) {
    case NSQUERY_A:
      fprintf(f, "A\t%u.%u.%u.%u\n", d[0], d[1], d[2], d[3]);
      break;
    case NSQUERY_TXT:
      fprintf(f, "TXT\t\"%.*s\"\n", *d, d + 1); /*XXX quotes */
      break;
    case NSQUERY_MX:
      dns_dntop(d + 3, name, sizeof(name));
      fprintf(f, "MX\t%u\t%s.\n",
              ((unsigned)d[1] << 8) | d[2],
              name);
      break;
    }
  }
}

#endif
