/* $Id$
 * Nameserver zones: structures and routines
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include "rbldnsd.h"

static struct dataset *ds_list;

static struct dataset *newdataset(char *spec) {
  /* type:file,file,file... */
  struct dataset *ds;
  char *f;
  struct dsfile **dsfp, *dsf;
  static const char *const delims = ",:";
  const struct dstype **dstp;

  f = strchr(spec, ':');
  if (!f)
    error(0, "invalid zone data specification `%.60s'", spec);
  *f++ = '\0';

  for(ds = ds_list; ds; ds = ds->ds_next)
    if (strcmp(ds->ds_type->dst_name, spec) == 0 &&
        strcmp(ds->ds_spec, f) == 0)
      return ds;

  dstp = ds_types;
  while(strcmp(spec, (*dstp)->dst_name))
    if (!*++dstp)
      error(0, "unknown dataset type `%.60s'", spec);
  ds = (struct dataset*)ezalloc(sizeof(struct dataset) +
                                     sizeof(struct mempool) +
                                     (*dstp)->dst_size);
  ds->ds_type = *dstp;
  ds->ds_mp = (struct mempool*)(ds + 1);
  ds->ds_dsd = (struct dsdata*)(ds->ds_mp + 1);
  ds->ds_spec = estrdup(f);

  ds->ds_next = ds_list;
  ds_list = ds;

  dsfp = &ds->ds_dsf;
  for (f = strtok(f, delims); f; f = strtok(NULL, delims)) {
    dsf = tmalloc(struct dsfile);
    dsf->dsf_stamp = 0;
    dsf->dsf_name = estrdup(f);
    *dsfp = dsf;
    dsfp = &dsf->dsf_next;
  }
  *dsfp = NULL;
  if (!ds->ds_dsf)
    error(0, "missing filenames for %s", spec);

  return ds;
}

struct zone *newzone(struct zone **zonelist,
                     unsigned char *dn, unsigned dnlen,
                     struct mempool *mp) {
  struct zone *zone, **zonep, **lastzonep;
 
  zonep = zonelist;
  lastzonep = NULL;

  for (;;) {
    if (!(zone = *zonep)) {
      if (mp)
        zone = mp_talloc(mp, struct zone);
      else
        zone = tmalloc(struct zone);
      if (!zone)
        return NULL;
      memset(zone, 0, sizeof(*zone));
      if (lastzonep) { zone->z_next = *lastzonep; *lastzonep = zone; }
      else *zonep = zone;
      memcpy(zone->z_dn, dn, dnlen);
      zone->z_dnlen = dnlen;
      zone->z_dnlab = dns_dnlabels(dn);
      zone->z_dslp = &zone->z_dsl;
      break;
    }
    else if (zone->z_dnlen == dnlen && memcmp(zone->z_dn, dn, dnlen) == 0)
      break;
    else {
      if (!lastzonep && zone->z_dnlen < dnlen &&
          memcmp(dn + dnlen - zone->z_dnlen, zone->z_dn, zone->z_dnlen) == 0)
        lastzonep = zonep;
      zonep = &zone->z_next;
    }
  }

  return zone;
}

void connectdataset(struct zone *zone,
                    struct dataset *ds,
                    struct dslist *dsl) {
  dsl->dsl_next = NULL;
  *zone->z_dslp = dsl;
  zone->z_dslp = &dsl->dsl_next;
  dsl->dsl_ds = ds;
  dsl->dsl_queryfn = ds->ds_type->dst_queryfn;
  zone->z_dstflags |= ds->ds_type->dst_flags;
}

struct zone *addzone(struct zone *zonelist, const char *spec) {
  struct zone *zone;
  char *p;
  char name[DNS_MAXDOMAIN];
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;

  p = strchr(spec, ':');
  if (!p || p - spec >= DNS_MAXDOMAIN)
    error(0, "invalid zone spec `%.60s'", spec);

  memcpy(name, spec, p - spec);
  name[p - spec] = '\0';

  dnlen = dns_ptodn(name, dn, sizeof(dn));
  if (!dnlen)
    error(0, "invalid domain name `%.80s'", name);

  zone = newzone(&zonelist, dn, dnlen, NULL);

  p = estrdup(p+1);
  connectdataset(zone, newdataset(p), tmalloc(struct dslist));
  free(p);

  return zonelist;
}

/* parse $SPECIAL construct */
int ds_special(struct dataset *ds, char *line, int lineno) {

  switch(*line) {

  case 's': case 'S':

  if ((line[1] == 'o' || line[1] == 'O') &&
      (line[2] == 'a' || line[2] == 'A') &&
      ISSPACE(line[3])) {

    /* SOA record */
    struct dssoa dssoa;
    unsigned char odn[DNS_MAXDN], pdn[DNS_MAXDN];
    unsigned odnlen, pdnlen;

    if (ds->ds_dssoa)
      return 1; /* ignore if already set */

    line += 4;
    SKIPSPACE(line);

    if (!(line = parse_ttl_nb(line, dssoa.dssoa_ttl, ds->ds_ttl))) return 0;
    if (!(line = parse_dn(line, odn, &odnlen))) return 0;
    if (!(line = parse_dn(line, pdn, &pdnlen))) return 0;
    if (!(line = parse_uint32(line, &dssoa.dssoa_serial))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+0))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+4))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+8))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+12))) return 0;
    if (*line) return 0;

    dssoa.dssoa_odn = mp_memdup(ds->ds_mp, odn, odnlen);
    dssoa.dssoa_pdn = mp_memdup(ds->ds_mp, pdn, pdnlen);
    if (!dssoa.dssoa_odn || !dssoa.dssoa_pdn) return -1;
    ds->ds_dssoa = mp_talloc(ds->ds_mp, struct dssoa);
    if (!ds->ds_dssoa) return -1;
    *ds->ds_dssoa = dssoa;

    return 1;
  }
  break;

  case 'n': case 'N':

  if ((line[1] == 's' || line[1] == 'S') &&
      ISSPACE(line[2])) {

     unsigned char dn[DNS_MAXDN], ttl[4];
     unsigned dnlen;
     struct dsns *dsns;

     line += 3;
     SKIPSPACE(line);

     if (!(line = parse_ttl_nb(line, ttl, ds->ds_ttl))) return 0;

     if (!(line = parse_dn(line, dn, &dnlen))) return 0;

     dsns = (struct dsns*)
       mp_alloc(ds->ds_mp, sizeof(struct dsns) + dnlen - 1, 1);
     if (!dsns) return -1;

     memcpy(dsns->dsns_dn, dn, dnlen);
     memcpy(dsns->dsns_ttl, ttl, 4);
     dsns->dsns_next = NULL;
     *ds->ds_dsnslp = dsns;
     ds->ds_dsnslp = &dsns->dsns_next;

     return 1;
  }
  break;

  case 't': case 'T':
  if ((line[1] == 't' || line[1] == 'T') &&
      (line[2] == 'l' || line[2] == 'L') &&
      ISSPACE(line[3])) {
    unsigned char ttl[4];
    line += 4;
    SKIPSPACE(line);
    if (!(line = parse_ttl_nb(line, ttl, def_ttl))) return 0;
    if (*line) return 0;
    if (ds->ds_subset) ds = ds->ds_subset;
    memcpy(ds->ds_ttl, ttl, 4);
    return 1;
  }
  break;

  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
  if (ISSPACE(line[1])) {
    /* substitution vars */
    unsigned n = line[0] - '0';
    if (ds->ds_subset) ds = ds->ds_subset;
    if (ds->ds_subst[n]) return 1; /* ignore second assignment */
    line += 2;
    SKIPSPACE(line);
    if (!*line) return 0;
    if (!(ds->ds_subst[n] = estrdup(line))) return 0;
    return 1;
  }
  break;

  case 'd': case 'D':
  if ((line[1] == 'A' || line[1] == 'a') &&
      (line[2] == 'T' || line[2] == 't') &&
      (line[3] == 'A' || line[3] == 'a') &&
      (line[4] == 'S' || line[4] == 's') &&
      (line[5] == 'E' || line[5] == 'e') &&
      (line[6] == 'T' || line[6] == 't') &&
      ISSPACE(line[7]) &&
      ds->ds_type == &dataset_combined_type) {
    line += 8;
    SKIPSPACE(line);
    return ds_combined_newset(ds, line, lineno);
  }
  break;

  }

  return 0;
}

static void freedataset(struct dataset *ds) {
  ds->ds_type->dst_resetfn(ds->ds_dsd, 0);
  mp_free(ds->ds_mp);
  ds->ds_dssoa = NULL;
  memcpy(ds->ds_ttl, def_ttl, 4);
  ds->ds_dsns = NULL;
  ds->ds_dsnslp = &ds->ds_dsns;
  memset(ds->ds_subst, 0, sizeof(ds->ds_subst));
  ds->ds_warn = 0;
  ds->ds_subset = NULL;
}

static int loaddataset(struct dataset *ds) {
  struct dsfile *dsf;
  time_t stamp = 0;
  FILE *f;

  freedataset(ds);

  ds_loading = ds;

  for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
    ds->ds_fname = dsf->dsf_name;
    f = fopen(dsf->dsf_name, "r");
    if (!f) {
      dslog(LOG_ERR, 0, "unable to open file: %s", strerror(errno));
      return 0;
    }
    ds->ds_type->dst_startfn(ds);
    if (!readdslines(f, ds)) {
      fclose(f);
      return 0;
    }
    if (ferror(f)) {
      dslog(LOG_ERR, 0, "error reading file: %s", strerror(errno));
      fclose(f);
      return 0;
    }
    fclose(f);
    if (dsf->dsf_stamp > stamp)
      stamp = dsf->dsf_stamp;
  }
  ds->ds_fname = NULL;
  ds->ds_stamp = stamp;

  ds->ds_type->dst_finishfn(ds);

  ds_loading = NULL;

  return 1;
}

static int updatezone(struct zone *zone) {
  time_t stamp = 0;
  const struct dssoa *dssoa = NULL;
  const struct dsns *dsns;
  const struct dsns *dsnsa[MAX_NS];
  unsigned n, nns;
  struct dslist *dsl;

  nns = 0;

  for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next) {
    const struct dataset *ds = dsl->dsl_ds;
    if (!ds->ds_stamp)
      return 0;
    if (stamp < ds->ds_stamp)
      stamp = ds->ds_stamp;
    if (!dssoa)
      dssoa = ds->ds_dssoa;
    for(dsns = ds->ds_dsns; dsns; dsns = dsns->dsns_next) {
      for(n = 0; ; ++n) {
        if (n == nns) {
          if (n < MAX_NS)
            dsnsa[nns++] = dsns;
          break;
        }
        if (dns_dnequ(dsnsa[n]->dsns_dn, dsns->dsns_dn))
          break;
      }
    }
  }
  zone->z_stamp = stamp;
  if (!update_zone_soa(zone, dssoa) ||
      !update_zone_ns(zone, dsnsa, nns)) {
    char name[DNS_MAXDOMAIN+1];
    dns_dntop(zone->z_dn, name, sizeof(name));
    dslog(LOG_WARNING, 0,
          "zone %.70s: NS or SOA RRs are too long, will be ignored", name);
  }

  return 1;
}

int reloadzones(struct zone *zonelist) {
  struct dataset *ds;
  struct dsfile *dsf;
  int reloaded = 0;
  int errors = 0;

  for(ds = ds_list; ds; ds = ds->ds_next) {
    int load = 0;

    ds_loading = ds;

    for(dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next) {
      struct stat st;
      if (stat(dsf->dsf_name, &st) < 0) {
        dslog(LOG_ERR, 0, "unable to stat file `%.60s': %s",
             dsf->dsf_name, strerror(errno));
        load = -1;
        break;
      }
      else if (dsf->dsf_stamp != st.st_mtime) {
        load = 1;
        dsf->dsf_stamp = st.st_mtime;
      }
    }

    if (!load)
      continue;

    ++reloaded;

    if (load < 0 || !loaddataset(ds)) {
      ++errors;
      freedataset(ds);
      for (dsf = ds->ds_dsf; dsf; dsf = dsf->dsf_next)
        dsf->dsf_stamp = 0;
      ds->ds_stamp = 0;
    }

  }

  ds_loading = NULL;

  if (reloaded) {

    for(; zonelist; zonelist = zonelist->z_next) {
      if (!updatezone(zonelist)) {
        char name[DNS_MAXDOMAIN+1];
        dns_dntop(zonelist->z_dn, name, sizeof(name));
        dslog(LOG_WARNING, 0, "zone %.70s will not be serviced", name);
        zonelist->z_stamp = 0;
      }
    }

  }

  return errors ? -1 : reloaded ? 1 : 0;
}

void dumpzone(const struct zone *z, FILE *f) {
  const struct dslist *dsl;
  { /* zone header */
    char name[DNS_MAXDOMAIN+1];
    const struct dsns **dsnsa = z->z_dsnsa;
    const struct dssoa *dssoa = z->z_dssoa;
    unsigned nns = z->z_nns;
    unsigned n;
    dns_dntop(z->z_dn, name, sizeof(name));
    fprintf(f, "$ORIGIN\t%s.\n", name);
    if (z->z_dssoa) {
      fprintf(f, "@\t%u\tSOA", unpack32(dssoa->dssoa_ttl));
      dns_dntop(dssoa->dssoa_odn, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      dns_dntop(dssoa->dssoa_pdn, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      fprintf(f, "\t(%u %u %u %u %u)\n",
          dssoa->dssoa_serial ? dssoa->dssoa_serial : z->z_stamp,
          unpack32(dssoa->dssoa_n+0),
          unpack32(dssoa->dssoa_n+4),
          unpack32(dssoa->dssoa_n+8),
          unpack32(dssoa->dssoa_n+12));
    }
    for(n = 0; n < nns; ++n) {
      dns_dntop(dsnsa[n]->dsns_dn, name, sizeof(name));
      fprintf(f, "\t%u\tNS\t%s.\n", unpack32(dsnsa[n]->dsns_ttl), name);
    }
  }
  for (dsl = z->z_dsl; dsl; dsl = dsl->dsl_next) {
    fprintf(f, "$TTL %u\n", unpack32(dsl->dsl_ds->ds_ttl));
    dsl->dsl_ds->ds_type->dst_dumpfn(dsl->dsl_ds, z->z_dn, f);
  }
}
