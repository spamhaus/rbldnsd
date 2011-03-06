/* combined dataset, one file is a collection of various datasets
 * and subzones.  Special case.
 */

#include <string.h>
#include <syslog.h>
#include <stdlib.h>
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
  struct dataset **dslastp;		/* where to connect next dataset */
  unsigned nds;				/* number of datasets in dslist */
  struct dataset *sdslist;		/* saved datasets list */
  struct zone *zlist;			/* list of subzones */
};

definedstype(combined, DSTF_SPECIAL, "several datasets/subzones combined");

static void ds_combined_reset(struct dsdata *dsd, int freeall) {
  struct dataset *dslist = dsd->dslist;
  while(dslist) {
    struct dataset *ds = dslist;
    dslist = dslist->ds_next;
    ds->ds_type->dst_resetfn(ds->ds_dsd, freeall);
    if (freeall) free(ds);
  }
  dslist = dsd->sdslist;
  while(dslist) {
    struct dataset *ds = dslist;
    dslist = dslist->ds_next;
    ds->ds_type->dst_resetfn(ds->ds_dsd, 1);
    free(ds);
  }
  dslist = dsd->dslist;
  memset(dsd, 0, sizeof(*dsd));
  if (!freeall) dsd->sdslist = dslist;
  dsd->dslastp = &dsd->dslist;
}

static int
ds_combined_line(struct dataset UNUSED *unused_ds,
                 char UNUSED *unused_s, struct dsctx *dsc) {
  dslog(LOG_ERR, dsc, "invalid/unrecognized entry - specify $DATASET line");
  return 0;
}

static void ds_combined_finishlast(struct dsctx *dsc) {
  struct dataset *dssub = dsc->dsc_subset;
  if (dssub) {
    const char *fname = dsc->dsc_fname;
    dsc->dsc_fname = NULL;
    dssub->ds_type->dst_finishfn(dssub, dsc);
    dsc->dsc_subset = NULL;
    dsc->dsc_fname = fname;
  }
}

static void ds_combined_start(struct dataset UNUSED *ds) {
}

static void ds_combined_finish(struct dataset *ds, struct dsctx *dsc) {
  struct dsdata *dsd = ds->ds_dsd;
  struct zone *zone;
  unsigned nzones;
  ds_combined_finishlast(dsc);
  for(nzones = 0, zone = dsd->zlist; zone; zone = zone->z_next)
    ++nzones;
  dsloaded(dsc, "subzones=%u datasets=%u", nzones, dsd->nds);
}

int ds_combined_newset(struct dataset *ds, char *line, struct dsctx *dsc) {
  char *p;
  const char *const space = " \t";
  struct dsdata *dsd = ds->ds_dsd;
  struct dataset *dssub;
  struct dslist *dsl;
  struct zone *zone;
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;
  char *name;

  ds_combined_finishlast(dsc);

  /* remove comment. only recognize # after a space. */
  for (p = line; *p; ++p)
    if (ISCOMMENT(*p) && (p == line || ISSPACE(p[-1]))) {
      *p = '\0';
      break;
    }
  p = strtok(line, space);	/* dataset type */
  if (!p) return 0;
  if ((name = strchr(p, ':')) != NULL)
    *name++ = '\0';

  for(;;) {	/* search appropriate dataset */

    if (!(dssub = dsd->sdslist)) {
      /* end of the saved list, allocate new dataset */
      const struct dstype **dstp = ds_types, *dst;
      dstp = ds_types;
      while(strcmp(p, (*dstp)->dst_name))
        if (!*++dstp) {
          dslog(LOG_ERR, dsc, "unknown dataset type `%.60s'", p);
          return -1;
        }
      dst = *dstp;
      if (dst->dst_flags & DSTF_SPECIAL) {
        dslog(LOG_ERR, dsc,
              "dataset type `%s' cannot be used inside `combined'",
              dst->dst_name);
        return -1;
      }
      dssub = (struct dataset *)
        ezalloc(sizeof(struct dataset) + dst->dst_size);
      if (!dssub)
        return -1;
      dssub->ds_type = dst;
      dssub->ds_dsd = (struct dsdata *)(dssub + 1);
      dssub->ds_mp = ds->ds_mp;	/* use parent memory pool */
      break;
    }

    else if (strcmp(dssub->ds_type->dst_name, p) == 0) {
      /* reuse existing one */
      dsd->sdslist = dssub->ds_next;
      break;
    }

    else {
      /* entry is of different type, free it and try next one */
      dsd->sdslist = dssub->ds_next;
      dssub->ds_type->dst_resetfn(dssub->ds_dsd, 1);
      free(dssub);
    }

  }

  dssub->ds_next = NULL;
  *dsd->dslastp = dssub;
  dsd->dslastp = &dssub->ds_next;
  if (name && *name) {
    if (strlen(name) > 20) name[20] = '\0';
    if (!(dssub->ds_spec = mp_strdup(ds->ds_mp, name)))
      return -1;
  }

  if (!(p = strtok(NULL, space)))
    dswarn(dsc, "no subzone(s) specified for dataset, data will be ignored");
  else do {
    if (p[0] == '@' && p[1] == '\0') {
      dn[0] = '\0';
      dnlen = 1;
    }
    else if (!(dnlen = dns_ptodn(p, dn, sizeof(dn)))) {
      dswarn(dsc, "invalid domain name `%.60s'", p);
      continue;
    }
    else
      dns_dntol(dn, dn);
    zone = newzone(&dsd->zlist, dn, dnlen, ds->ds_mp);
    dsl = mp_talloc(ds->ds_mp, struct dslist);
    if (!zone || !dsl) return -1;
    connectdataset(zone, dssub, dsl);
  } while((p = strtok(NULL, space)) != NULL);

  ++dsd->nds;
  dsc->dsc_subset = dssub;
  dssub->ds_type->dst_resetfn(dssub->ds_dsd, 0);
  dssub->ds_ttl = ds->ds_ttl;
  memcpy(dssub->ds_subst, ds->ds_subst, sizeof(ds->ds_subst));
  dssub->ds_type->dst_startfn(dssub);

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
    found |= dsl->dsl_queryfn(dsl->dsl_ds, &sqi, pkt);
  /* if it was a query for our base subzone, always return `found' */
  return found | (sqi.qi_dnlab ? 0 : NSQUERY_FOUND);
}

#ifndef NO_MASTER_DUMP

static void
ds_combined_dump(const struct dataset *ds, const unsigned char *odn, FILE *f) {
  char bname[DNS_MAXDOMAIN+1], sname[DNS_MAXDOMAIN+1];
  const struct zone *zone;
  const struct dslist *dsl;
  dns_dntop(odn, bname, DNS_MAXDOMAIN + 1);
  for(zone = ds->ds_dsd->zlist; zone; zone = zone->z_next) {
    if (zone->z_dnlen == 1)
      fprintf(f, "$ORIGIN %s.\n", bname);
    else {
      dns_dntop(zone->z_dn, sname, DNS_MAXDOMAIN + 1);
      fprintf(f, "$ORIGIN %s.%s.\n", sname, bname);
    }
    for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next)
      dsl->dsl_ds->ds_type->dst_dumpfn(dsl->dsl_ds, NULL/*XXX*/, f);
  }
}

#endif
