/* $Id$
 * generic dataset, simplified bind format.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rbldnsd.h"

struct entry {
  const unsigned char *ldn;	/* DN, first byte is length, w/o EON */
  unsigned dtyp;		/* data (query) type */
    /* last word is DNS RR type, first word is NSQUERY_XX bit */
  unsigned char *data;	/* data, mp-allocated (size depends on qtyp) */
    /* first 4 bytes is ttl */
};

struct dataset {
  unsigned n;		/* number of entries */
  unsigned a;		/* entries allocated (only when loading) */
  struct entry *e;	/* entries */
  unsigned maxlab;	/* max level of labels */
  unsigned minlab;	/* min level of labels */
};

definedstype(generic, DSTF_ZERODN, "generic simplified bind-format");

static void ds_generic_reset(struct dataset *ds) {
  if (ds->e) free(ds->e);
  memset(ds, 0, sizeof(*ds));
  ds->minlab = DNS_MAXDN;
}

static void ds_generic_start(struct zonedataset UNUSED *unused_zds) {
}

static int ds_generic_parseany(struct zonedataset *zds, char *s) {
  struct dataset *ds = zds->zds_ds;
  struct entry *e;
  char *t;
  unsigned dtyp, dsiz, dnlab;
  char data[DNS_MAXDN*2+20];
  char *dp;

  /* allocate new entry */
  e = ds->e;
  if (ds->n >= ds->a) {
    ds->a = ds->a ? ds->a << 1 : 8;
    e = trealloc(struct entry, e, ds->a);
    if (!e) return 0;
    ds->e = e;
  }
  e += ds->n;

  /* dn */
  if (s[0] == '@' && ISSPACE(s[1])) {
    data[1] = '\0';
    dsiz = 1;
    s += 2;
    SKIPSPACE(s);
  }
  else if (!(s = parse_dn(s, data + 1, &dsiz)) || dsiz == 1)
    return -1;
  dnlab = dns_dnlabels(data + 1);
  data[0] = (unsigned char)(dsiz - 1);
  if (!(e->ldn = mp_dmemdup(zds->zds_mp, data, dsiz)))
    return 0;

  SKIPSPACE(s);

  if (*s >= '0' && *s <= '9') { /* ttl */
    if (!(s = parse_ttl_nb(s, data, zds->zds_ttl))) return 0;
    SKIPSPACE(s);
  }
  else
    memcpy(data, zds->zds_ttl, 4);
  dp = data + 4;

  /* type */
  t = s;
  while(!ISSPACE(*s))
    if (!*s) return -1;
    else { *s = dns_dnlc(*s); ++s; }
  *s++ = '\0';
  SKIPSPACE(s);

  if (strcmp(t, "a") == 0) {
    ip4addr_t a;
    dtyp = NSQUERY_A | DNS_T_A;
    if (!ip4addr(s, &a, &s)) return -1;
    PACK32(dp, a);
    dsiz = 4;
  }

  else if (strcmp(t, "txt") == 0) {
    dtyp = NSQUERY_TXT | DNS_T_TXT;
    dsiz = strlen(s);
    if (dsiz >= 2 && s[0] == '"' && s[dsiz-1] == '"')
      ++s, dsiz -= 2;
    if (dsiz > 254) dsiz = 254;
    dp[0] = (char)dsiz;
    memcpy(dp+1, s, dsiz);
    dsiz += 1;
  }

  else if (strcmp(t, "mx") == 0) {
    dtyp = NSQUERY_MX | DNS_T_MX;
    if (!(s = parse_uint32_nb(s, dp)) || dp[0] || dp[1]) return -1;
    dp[0] = dp[2]; dp[1] = dp[3];
    if (!(s = parse_dn(s, dp + 3, &dsiz))) return 0;
    if (*s) return 0;
    dp[2] = (unsigned char)dsiz;
    dsiz += 3;
  }

  else
    return -1;

  e->dtyp = dtyp;
  dsiz += 4;
  if (!(e->data = mp_alloc(zds->zds_mp, dsiz, 0)))
    return 0;
  memcpy(e->data, data, dsiz);

  ++ds->n;
  if (ds->maxlab < dnlab) ds->maxlab = dnlab;
  if (ds->minlab > dnlab) ds->minlab = dnlab;

  return 1;
}

static int
ds_generic_line(struct zonedataset *zds, char *s, int lineno) {
  int r = ds_generic_parseany(zds, s);
  if (r < 0) {
    dswarn(lineno, "invalid/unrecognized entry");
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

static void ds_generic_finish(struct zonedataset *zds) {
  struct dataset *ds = zds->zds_ds;
  if (ds->n) {

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e
#   define QSORT_NELT ds->n
#   define QSORT_LT(a,b) \
  memcmp(a->ldn, b->ldn, a->ldn[0] + 1) < 0
#   include "qsort.c"

    /* collect all equal DNs to point to the same place */
    { struct entry *e, *t;
      for(e = ds->e, t = e + ds->n - 1; e < t; ++e)
        if (memcmp(e[0].ldn, e[1].ldn, e[0].ldn[0] + 1) == 0)
          e[1].ldn = e[0].ldn;
    }
    SHRINK_ARRAY(struct entry, ds->e, ds->n, ds->a);
  }
  dsloaded("e=%u", ds->n);
}

static int
ds_generic_query(const struct zonedataset *zds, const struct dnsqueryinfo *qi,
                 struct dnspacket *pkt) {
  const struct dataset *ds = zds->zds_ds;
  const unsigned char *dn = qi->qi_dn;
  const struct entry *e = ds->e, *t;
  unsigned qlen0 = qi->qi_dnlen0;
  const unsigned char *d;
  int a = 0, b = ds->n - 1, m, r;

  if (qi->qi_dnlab > ds->maxlab || qi->qi_dnlab < ds->minlab || b < 0)
    return 0;

  for(;;) {
    if (a > b) return 0;
    t = e + (m = (a + b) >> 1);
    if (t->ldn[0] < qlen0) a = m + 1;
    else if (t->ldn[0] > qlen0) b = m - 1;
    else if (!(r = memcmp(t->ldn + 1, dn, qlen0))) break;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }

  /* find first entry with the DN in question */
  dn = (t--)->ldn;
  while(t >= e && t->ldn == dn)
    --t;
  e = t + 1;

  t = ds->e + ds->n;
  do {
    if (!(qi->qi_tflag & e->dtyp))
      continue;
    d = e->data;
    switch(e->dtyp & 0xff) {
    case DNS_T_A:
      addrr_any(pkt, DNS_T_A, d + 4, 4, d);
      break;
    case DNS_T_TXT:
      addrr_any(pkt, DNS_T_TXT, d + 4, (unsigned)(d[4]) + 1, d);
      break;
    case DNS_T_MX:
      addrr_mx(pkt, d + 4, d + 7, d[4], d);
      break;
    }
  } while(++e < t && e->ldn == dn);
  return 1;
}

static void
ds_generic_dump(const struct zonedataset *zds,
                const unsigned char UNUSED *unused_odn,
                FILE *f) {
  const struct dataset *ds = zds->zds_ds;
  const struct entry *e, *t;
  char name[DNS_MAXDOMAIN+1];
  const unsigned char *ldn = NULL;
  const unsigned char *d;

  for (e = ds->e, t = e + ds->n; e < t; ++e) {
    if (ldn != e->ldn) {
      ldn = e->ldn;
      if (ldn[0] > 1)
	dns_dntop(ldn + 1, name, sizeof(name));
      else
	strcpy(name, "@");
      d = name;
    }
    else
      d = "";
    fprintf(f, "%s\t%u\t", d, unpack32(e->data));
    d = e->data + 4;
    switch(e->dtyp & 0xff) {
    case DNS_T_A:
      fprintf(f, "A\t%u.%u.%u.%u\n", d[0], d[1], d[2], d[3]);
      break;
    case DNS_T_TXT:
      fprintf(f, "TXT\t\"%.*s\"\n", *d, d + 1); /*XXX quotes */
      break;
    case DNS_T_MX:
      dns_dntop(d + 3, name, sizeof(name));
      fprintf(f, "MX\t%u\t%s.\n",
              ((unsigned)d[0] << 8) | d[1],
              name);
      break;
    }
  }
}
