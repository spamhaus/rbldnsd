/* $Id$
 * combined dataset, one file is a collection of various datasets
 * and subzones.  Special case.
 */

#include <string.h>
#include <syslog.h>
#include "rbldnsd.h"

/* Special "dataset", which does NOT contain any data itself,
 * but contains several datasets of other types instead.
 * Operations:
 *  we have a list of datasets in dslist, that contains
 *   our data (subdataset)
 *  when loading, we have current dataset in dssub, which
 *   will be called to parse a line
 *  we have a list of subzones in zlist for query
 */

struct dsdata {
  struct dataset *dslist;		/* list of subzone datasets */
  unsigned nds;				/* number of datasets in dslist */
  struct zone *zlist;			/* list of subzones */
};

definedstype(combined, 0, "several datasets/subzones combined");

static void ds_combined_reset(struct dsdata *dsd, int UNUSED unused_freeall) {
  struct dataset *ds;
  for(ds = dsd->dslist; ds; ds = ds->ds_next)
    ds->ds_type->dst_resetfn(ds->ds_dsd, 1);
  memset(dsd, 0, sizeof(*dsd));
}

static int
ds_combined_line(struct dataset UNUSED *unused_ds,
                 char UNUSED *unused_s, int lineno) {
  dslog(LOG_ERR, lineno, "invalid/unrecognized entry - specify $DATASET line");
  return 0;
}

static void ds_combined_finishlast(struct dataset *ds) {
  struct dataset *dssub = ds->ds_subset;
  if (dssub) {
    const char *fname = ds->ds_fname;
    ds->ds_fname = NULL;
    dssub->ds_type->dst_finishfn(dssub);
    ds->ds_subset = NULL;
    ds->ds_fname = fname;
  }
}

static void ds_combined_start(struct dataset *ds) {
  ds_combined_finishlast(ds);
}

static void ds_combined_finish(struct dataset *ds) {
  struct dsdata *dsd = ds->ds_dsd;
  struct zone *zone;
  unsigned nzones;
  ds_combined_finishlast(ds);
  for(nzones = 0, zone = dsd->zlist; zone; zone = zone->z_next)
    ++nzones;
  dsloaded("subzones=%u datasets=%u", nzones, dsd->nds);
}

int ds_combined_newset(struct dataset *ds, char *line, int lineno) {
  char *p;
  const char *const space = " \t";
  struct dsdata *dsd = ds->ds_dsd;
  const struct dstype **dstp, *dst;
  struct dataset *dssub;
  struct dslist *dsl;
  struct zone *zone;
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;

  ds_combined_finishlast(ds);

  p = line;
  while(*p && !ISCOMMENT(*p))
    ++p;
  *p = '\0';
  p = strtok(line, space);	/* dataset type */
  if (!p) return 0;
  dstp = ds_types;
  while(*dstp == &dataset_combined_type || strcmp(p, (*dstp)->dst_name))
    if (!*++dstp) {
      dslog(LOG_ERR, lineno, "unknown dataset type `%.60s'", p);
      return -1;
    }
  dst = *dstp;

  dssub = (struct dataset *)
     mp_alloc(ds->ds_mp, sizeof(struct dataset) + dst->dst_size, 1);
  if (!dssub)
    return -1;
  memset(dssub, 0, sizeof(struct dataset) + dst->dst_size);
  dssub->ds_type = dst;
  dssub->ds_dsd = (struct dsdata *)(dssub + 1);
  dssub->ds_mp = ds->ds_mp;	/* use parent memory pool */

  dssub->ds_next = dsd->dslist;
  dsd->dslist = dssub;

  while((p = strtok(NULL, space)) != NULL) {
    if (p[0] == '@' && p[1] == '\0') {
      dn[0] = '\0';
      dnlen = 1;
    }
    else if (!(dnlen = dns_ptodn(p, dn, sizeof(dn)))) {
      dswarn(lineno, "invalid domain name `%.60s'", p);
      continue;
    }
    zone = newzone(&dsd->zlist, dn, dnlen, ds->ds_mp);
    dsl = mp_talloc(ds->ds_mp, struct dslist);
    if (!zone || !dsl) return -1;
    connectdataset(zone, dssub, dsl);
  }

  ++dsd->nds;
  ds->ds_subset = dssub;
  dst->dst_resetfn(dssub->ds_dsd, 0);
  memcpy(dssub->ds_ttl, ds->ds_ttl, 4);
  memcpy(dssub->ds_subst, ds->ds_subst, sizeof(ds->ds_subst));
  dst->dst_startfn(dssub);

  return 1;
}

static int
ds_combined_query(const struct dataset *ds, const struct dnsqinfo *qi,
                  struct dnspacket *pkt) {
  struct dnsqinfo sqi;
  const struct dslist *dsl;
  int found = 0;
  const struct zone *zone =
    findqzone(ds->ds_dsd->zlist,
              qi->qi_dnlen0 + 1, qi->qi_dnlab, qi->qi_dnlptr,
              &sqi);
  if (!zone) return 0;
  sqi.qi_tflag = qi->qi_tflag;
  for (dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next)
    if (dsl->dsl_queryfn(dsl->dsl_ds, &sqi, pkt))
      found = 1;
  return found;
}

static void
ds_combined_dump(const struct dataset *ds, const unsigned char *odn, FILE *f) {
  char name[DNS_MAXDOMAIN*2+3];
  unsigned l = dns_dntop(odn, name, DNS_MAXDOMAIN + 1);
  const struct zone *zone;
  const struct dslist *dsl;
  for(zone = ds->ds_dsd->zlist; zone; zone = zone->z_next) {
    if (zone->z_dnlen == 1)
      name[l] = '\0';
    else {
      name[l] = '.';
      dns_dntop(zone->z_dn, name + l + 1, DNS_MAXDOMAIN + 1);
    }
    fprintf(f, "$ORIGIN %s.\n", name);
    for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next)
      dsl->dsl_ds->ds_type->dst_dumpfn(dsl->dsl_ds, NULL/*XXX*/, f);
  }
}
