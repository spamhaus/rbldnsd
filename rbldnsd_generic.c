/* $Id$
 * generic dataset, simplified bind format.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

definedstype(generic, DSTF_DNREV, "generic simplified bind-format");

struct entry {
  const unsigned char *lrdn;
  	/* reversed DN, mp-allocated; first byte is length */
  unsigned dtyp;	/* data (query) type */
    /* last word is DNS RR type, first word is NSQUERY_XX bit */
  unsigned char *data;	/* data, mp-allocated (size depends on qtyp) */
};

struct dataset {
  unsigned n;		/* number of entries */
  unsigned a;		/* entries allocated (only when loading) */
  struct entry *e;	/* entries */
  unsigned maxlab;	/* max level of labels */
  struct mempool mp;	/* mempool for domain names and RR data */
};

static void ds_generic_free(struct dataset *ds) {
  if (ds) {
    mp_free(&ds->mp);
    if (ds->e) free(ds->e);
    free(ds);
  }
}

static int ds_generic_parseany(struct dataset *ds, char *line) {
  struct entry *e;
  char *t;
  unsigned dtyp, dsiz;
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
  if (!(line = parse_dn(line, data + DNS_MAXDN + 1, &dsiz)) || dsiz == 1)
    return -1;
  data[0] = (unsigned char)dsiz;
  dns_dnreverse(data + DNS_MAXDN + 1, data, dsiz);
  if (!(e->lrdn = mp_dmemdup(&ds->mp, data, dsiz + 1)))
    return 0;

  skipspace(line);

  /* type */
  t = line;
  while(*line != ' ' && *line != '\t')
    if (!*line) return -1;
    else { *line = dns_dnlc(*line); ++line; }
  *line++ = '\0';
  skipspace(line);

  dp = data;

  if (strcmp(t, "a") == 0) {
    ip4addr_t a;
    dtyp = NSQUERY_A | DNS_T_A;
    if (!ip4addr(line, &a, &line)) return -1;
    a = htonl(a);
    memcpy(data, &a, 4);
    dsiz = 4;
  }

  else if (strcmp(t, "txt") == 0) {
    dtyp = NSQUERY_TXT | DNS_T_TXT;
    dsiz = strlen(line);
    if (dsiz >= 2 && line[0] == '"' && line[dsiz-1] == '"')
      ++line, dsiz -= 2;
    if (dsiz > 254) dsiz = 254;
    data[0] = (char)dsiz;
    memcpy(data+1, line, dsiz);
    dsiz += 1;
  }

  else
    return -1;

  e->dtyp = dtyp;
  if (!(e->data = mp_alloc(&ds->mp, dsiz)))
    return 0;
  memcpy(e->data, data, dsiz);

  ++ds->n;
  dsiz = dns_dnlabels(e->lrdn);
  if (ds->maxlab < dsiz) ds->maxlab = dsiz;

  return 1;
}

static int
ds_generic_parseline(struct dataset *ds, char *line, int lineno) {
  int r = ds_generic_parseany(ds, line);
  if (r < 0) {
    dswarn(lineno, "invalid/unrecognized entry");
    return 1;
  }
  else if (!r)
    return 0;
  else
    return 1;
}

static int ds_generic_load(struct zonedataset *zds, FILE *f) {
  return readdslines(f, zds, ds_generic_parseline);
}

static struct dataset *ds_generic_alloc() {
  return tzalloc(struct dataset);
}

#define min(a,b) ((a)<(b)?(a):(b))

/* comparision of first MINlen bytes of two DNs is sufficient
 * due to the nature of domain name representation */

static int ds_generic_finish(struct dataset *ds) {
  if (ds->n) {

#   define QSORT_TYPE struct entry
#   define QSORT_BASE ds->e
#   define QSORT_NELT ds->n
#   define QSORT_LT(a,b) \
  memcmp(a->lrdn + 1, b->lrdn + 1, min(a->lrdn[0], b->lrdn[0])) < 0
#   include "qsort.c"

    /* collect all equal DNs to point to the same place */
    { struct entry *e, *t;
      for(e = ds->e, t = e + ds->n - 1; e < t; ++e)
        if (e[0].lrdn != e[1].lrdn && e[0].lrdn[0] == e[1].lrdn[0] &&
            memcmp(e[0].lrdn, e[1].lrdn, e[0].lrdn[0]) == 0)
          e[1].lrdn = e[0].lrdn;
    }
    SHRINK_ARRAY(struct entry, ds->e, ds->n, ds->a);
  }
  dsloaded("e=%u", ds->n);
  return 1;
}

static int
ds_generic_query(const struct dataset *ds, const struct dnsquery *query,
                 struct dnspacket *packet) {
  const unsigned char *rdn = query->q_rdn;
  const struct entry *e = ds->e, *t;
  unsigned qlen = query->q_dnlen;
  int a = 0, b = ds->n - 1, m, r;
  if (query->q_dnlab > ds->maxlab || b < 0) return 0;

  for(;;) {
    if (a > b) {
      /* we should not return NXDOMAIN if a subdomain of a query exists */
      if ((unsigned)a < ds->n && qlen < e[a].lrdn[0] &&
          memcmp(rdn, e[a].lrdn + 1, qlen - 1) == 0)
       return 1;
      return 0;
    }
    t = e + (m = (a + b) >> 1);
    if (!(r = memcmp(t->lrdn + 1, rdn, min(qlen, t->lrdn[0])))) break;
    else if (r < 0) a = m + 1;
    else b = m - 1;
  }

  /* find first entry with the DN in question */
  rdn = (t--)->lrdn;
  while(t >= e && t->lrdn == rdn)
    --t;
  e = t + 1;

  t = ds->e + ds->n;
  do {
    if (!(query->q_tflag & e->dtyp))
      continue;
    switch(e->dtyp & 0xff) {
    case DNS_T_A:
      addrr_any(packet, DNS_T_A, e->data, 4);
      break;
    case DNS_T_TXT:
      addrr_any(packet, DNS_T_TXT, e->data, (unsigned)(e->data[0]) + 1);
      break;
    }
  } while(++e < t && e->lrdn == rdn);
  return 1;
}
