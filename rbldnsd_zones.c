/* $Id$
 * Nameserver zones: structures and routines
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include "rbldnsd.h"

static struct dataset *ds_list;

struct dataset *ds_loading;

static void
vdslog(int level, int lineno, const char *fmt, va_list ap) {
  char buf[1024];
  int pl, l;
  if ((logto & LOGTO_STDOUT) ||
      (level <= LOG_WARNING && (logto & LOGTO_STDERR)))
    l = pl = ssprintf(buf, sizeof(buf), "%.30s: ", progname);
  else if (!(logto & LOG_SYSLOG))
    return;
  else
    l = pl = 0;
  if (ds_loading) {
    l += ssprintf(buf + l, sizeof(buf) - l, "%s:%.60s:",
                  ds_loading->ds_type->dst_name, ds_loading->ds_spec);
    if (ds_loading->ds_subset)
      l += ssprintf(buf + l, sizeof(buf) - l, "%s:",
                    ds_loading->ds_subset->ds_type->dst_name);
    if (ds_loading->ds_fname) {
      l += ssprintf(buf + l, sizeof(buf) - l, " %.60s",
                    ds_loading->ds_fname);
      l += ssprintf(buf + l, sizeof(buf) - l,
                    lineno ? "(%d): " : ": ", lineno);
    }
    else
      l += ssprintf(buf + l, sizeof(buf) - l, " ");
  }
  l += vssprintf(buf + l, sizeof(buf) - l, fmt, ap);
  if (logto & LOGTO_SYSLOG) {
    fmt = buf + pl;
    syslog(level, strchr(fmt, '%') ? "%s" : fmt, fmt);
  }
  if (logto & (LOGTO_STDOUT | LOGTO_STDERR)) {
    buf[l++] = '\n';
    write(level <= LOG_WARNING ? 2 : 1, buf, l);
  }
}

void dslog(int level, int lineno, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vdslog(level, lineno, fmt, ap);
  va_end(ap);
}

#define MAXWARN 5

void dswarn(int lineno, const char *fmt, ...) {
  if (++ds_loading->ds_warn <= MAXWARN) { /* prevent syslog flood */
    va_list ap;
    va_start(ap, fmt);
    dslog(LOG_WARNING, lineno, fmt, ap);
    va_end(ap);
  }
}

void dsloaded(const char *fmt, ...) {
  va_list ap;
  ds_loading->ds_fname = NULL;
  if (ds_loading->ds_warn > MAXWARN)
    dslog(LOG_WARNING, 0, "%d more warnings suppressed",
          ds_loading->ds_warn - MAXWARN);
  va_start(ap, fmt);
  if (ds_loading->ds_subset)
     vdslog(LOG_INFO, 0, fmt, ap);
  else {
    struct tm *tm = gmtime(&ds_loading->ds_stamp);
    char buf[128];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    dslog(LOG_INFO, 0, "%04d%02d%02d %02d%02d%02d: %s",
          tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec,
          buf);
  }
  va_end(ap);
}

void zlog(const struct zone *z, int level, const char *fmt, ...) {
  char name[DNS_MAXDOMAIN+1];
  unsigned len = dns_dntop(z->z_dn, name, sizeof(name));
  char buf[512];
  va_list ap;
  if (len > 80) {
    name[70] = name[71] = name[72] = '.'; name[73] = '\0';
  }
  va_start(ap, fmt);
  vssprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  dslog(level, 0, "zone %s: %s", name, buf);
}

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
      init_zone_caches(zone);
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

  if ((line[0] == 's' || line[0] == 'S') &&
      (line[1] == 'o' || line[1] == 'O') &&
      (line[2] == 'a' || line[2] == 'A') &&
      ISSPACE(line[3])) {

    /* SOA record */
    struct dssoa dssoa;
    unsigned odnlen, pdnlen;
    unsigned char dn[DNS_MAXDN*2];

    if (ds->ds_dssoa)
      return 1; /* ignore if already set */

    line += 4;
    SKIPSPACE(line);

    if (!(line = parse_ttl_nb(line, dssoa.dssoa_ttl, ds->ds_ttl))) return 0;
    if (!(line = parse_dn(line, dn, &odnlen))) return 0;
    if (!(line = parse_dn(line, dn + odnlen, &pdnlen))) return 0;
    if (!(line = parse_uint32(line, &dssoa.dssoa_serial))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+0))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+4))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+8))) return 0;
    if (!(line = parse_time_nb(line, dssoa.dssoa_n+12))) return 0;
    if (*line) return 0;

    dssoa.dssoa_odn = mp_memdup(ds->ds_mp, dn, odnlen + pdnlen);
    if (!dssoa.dssoa_odn) return -1;
    dssoa.dssoa_pdn = dssoa.dssoa_odn + odnlen;
    dssoa.dssoa_odnlen = odnlen;
    dssoa.dssoa_pdnlen = pdnlen;
    ds->ds_dssoa = mp_talloc(ds->ds_mp, struct dssoa);
    if (!ds->ds_dssoa) return -1;
    *ds->ds_dssoa = dssoa;

    return 1;
  }

  if ((line[0] == 'n' || line[0] == 'N') &&
      (line[1] == 's' || line[1] == 'S') &&
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

     dsns->dsns_dnlen = dnlen;
     memcpy(dsns->dsns_dn, dn, dnlen);
     memcpy(dsns->dsns_ttl, ttl, 4);
     dsns->dsns_next = NULL;
     *ds->ds_dsnslp = dsns;
     ds->ds_dsnslp = &dsns->dsns_next;

     return 1;
  }

  if ((line[0] == 't' || line[0] == 'T') &&
      (line[1] == 't' || line[1] == 'T') &&
      (line[2] == 'l' || line[2] == 'L') &&
      ISSPACE(line[3])) {
    unsigned char ttl[4];
    line += 4;
    SKIPSPACE(line);
    if (!(line = parse_ttl_nb(line, ttl, defttl))) return 0;
    if (*line) return 0;
    if (ds->ds_subset) ds = ds->ds_subset;
    memcpy(ds->ds_ttl, ttl, 4);
    return 1;
  }

  if (line[0] >= '0' && line[0] <= '9' &&
      ISSPACE(line[1])) {
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

  if ((line[0] == 'D' || line[0] == 'd') &&
      (line[1] == 'A' || line[1] == 'a') &&
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

  return 0;
}

static void freedataset(struct dataset *ds) {
  ds->ds_type->dst_resetfn(ds->ds_dsd, 0);
  mp_free(ds->ds_mp);
  ds->ds_dssoa = NULL;
  memcpy(ds->ds_ttl, defttl, 4);
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
        if (dsnsa[n]->dsns_dnlen == dsns->dsns_dnlen &&
            dns_dnequ(dsnsa[n]->dsns_dn, dsns->dsns_dn))
          break;
      }
    }
  }
  zone->z_stamp = stamp;
  if (!update_zone_soa(zone, dssoa))
    zlog(zone, LOG_WARNING, "unable to initialize SOA structure");
  if (!update_zone_ns(zone, dsnsa, nns))
    zlog(zone, LOG_WARNING, "unable to initialize NS structure");

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
        zlog(zonelist, LOG_WARNING,
             "partially loaded zone will not be serviced");
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
