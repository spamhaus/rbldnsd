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
 *  we have a list of zonedatasets in zdslist, that contains
 *   our data (subdataset)
 *  when loading, we have current zonedataset in zdssub, which
 *   will be called to parse a line
 *  we have a list of subzones in zlist for query
 */

struct dataset {
  struct zonedataset *zdslist;		/* list of subzone datasets */
  unsigned ndatasets;			/* number of datasets in zdslist */
  struct zone *zlist;			/* list of subzones */
};

definedstype(combined, 0, "several datasets/subzones combined");

static void ds_combined_reset(struct dataset *ds, int UNUSED unused_freeall) {
  struct zonedataset *zds;
  for(zds = ds->zdslist; zds; zds = zds->zds_next)
    zds->zds_type->dst_resetfn(zds->zds_ds, 1);
  memset(ds, 0, sizeof(*ds));
}

static int
ds_combined_line(struct zonedataset UNUSED *unused_zds,
                 char UNUSED *unused_s, int lineno) {
  dslog(LOG_ERR, lineno, "invalid/unrecognized entry - specify $DATASET line");
  return 0;
}

static void ds_combined_finishlast(struct zonedataset *zds) {
  struct zonedataset *zdssub = zds->zds_subset;
  if (zdssub) {
    const char *fname = zds->zds_fname;
    zds->zds_fname = NULL;
    zdssub->zds_type->dst_finishfn(zdssub);
    zds->zds_subset = NULL;
    zds->zds_fname = fname;
  }
}

static void ds_combined_start(struct zonedataset *zds) {
  ds_combined_finishlast(zds);
}

static void ds_combined_finish(struct zonedataset *zds) {
  struct dataset *ds = zds->zds_ds;
  struct zone *zone;
  unsigned nzones;
  ds_combined_finishlast(zds);
  for(nzones = 0, zone = ds->zlist; zone; zone = zone->z_next)
    ++nzones;
  dsloaded("subzones=%u datasets=%u", nzones, ds->ndatasets);
}

int ds_combined_newset(struct zonedataset *zds, char *line, int lineno) {
  char *p;
  const char *const space = " \t";
  struct dataset *ds = zds->zds_ds;
  const struct dataset_type **dstp, *dst;
  struct zonedataset *zdssub;
  struct zonedatalist *zdl;
  struct zone *zone;
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;

  ds_combined_finishlast(zds);

  p = line;
  while(*p && !ISCOMMENT(*p))
    ++p;
  *p = '\0';
  p = strtok(line, space);	/* dataset type */
  if (!p) return 0;
  dstp = dataset_types;
  while(*dstp == &dataset_combined_type || strcmp(p, (*dstp)->dst_name))
    if (!*++dstp) {
      dslog(LOG_ERR, lineno, "unknown dataset type `%.60s'", p);
      return -1;
    }
  dst = *dstp;

  zdssub = (struct zonedataset *)
     mp_alloc(zds->zds_mp, sizeof(struct zonedataset) + dst->dst_size, 1);
  if (!zdssub)
    return -1;
  memset(zdssub, 0, sizeof(struct zonedataset) + dst->dst_size);
  zdssub->zds_type = dst;
  zdssub->zds_ds = (struct dataset *)(zdssub + 1);
  zdssub->zds_mp = zds->zds_mp;	/* use parent memory pool */

  zdssub->zds_next = ds->zdslist;
  ds->zdslist = zdssub;

  while((p = strtok(NULL, space)) != NULL) {
    if (p[0] == '@' && p[1] == '\0') {
      dn[0] = '\0';
      dnlen = 1;
    }
    else if (!(dnlen = dns_ptodn(p, dn, sizeof(dn)))) {
      dswarn(lineno, "invalid domain name `%.60s'", p);
      continue;
    }
    zone = newzone(&ds->zlist, dn, dnlen, zds->zds_mp);
    zdl = mp_talloc(zds->zds_mp, struct zonedatalist);
    if (!zone || !zdl) return -1;
    connectzonedataset(zone, zdssub, zdl);
  }

  ++ds->ndatasets;
  zds->zds_subset = zdssub;
  dst->dst_resetfn(zdssub->zds_ds, 0);
  memcpy(zdssub->zds_ttl, zds->zds_ttl, 4);
  memcpy(zdssub->zds_subst, zds->zds_subst, sizeof(zds->zds_subst));
  dst->dst_startfn(zdssub);

  return 1;
}

static int
ds_combined_query(const struct zonedataset *zds, const struct dnsqueryinfo *qi,
                  struct dnspacket *pkt) {
  struct dnsqueryinfo sqi;
  const struct zonedatalist *zdl;
  int found = 0;
  const struct zone *zone =
    findqzone(zds->zds_ds->zlist,
              qi->qi_dnlen0 + 1, qi->qi_dnlab, qi->qi_dnlptr,
              &sqi);
  if (!zone) return 0;
  sqi.qi_tflag = qi->qi_tflag;
  for (zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next)
    if (zdl->zdl_queryfn(zdl->zdl_zds, &sqi, pkt))
      found = 1;
  return found;
}

static void
ds_combined_dump(const struct zonedataset *zds, const unsigned char *odn,
                 FILE *f) {
  char name[DNS_MAXDOMAIN*2+3];
  unsigned l = dns_dntop(odn, name, DNS_MAXDOMAIN + 1);
  const struct zone *zone;
  const struct zonedatalist *zdl;
  for(zone = zds->zds_ds->zlist; zone; zone = zone->z_next) {
    if (zone->z_dnlen == 1)
      name[l] = '\0';
    else {
      name[l] = '.';
      dns_dntop(zone->z_dn, name + l + 1, DNS_MAXDOMAIN + 1);
    }
    fprintf(f, "$ORIGIN %s.\n", name);
    for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next)
      zdl->zdl_zds->zds_type->dst_dumpfn(zdl->zdl_zds, NULL/*XXX*/, f);
  }
}
