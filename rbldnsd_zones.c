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

  if ((line[0] == 's' || line[0] == 'S') &&
      (line[1] == 'o' || line[1] == 'O') &&
      (line[2] == 'a' || line[2] == 'A') &&
      ISSPACE(line[3])) {

    /* SOA record */
    struct zonesoa *zsoa = &ds->ds_zsoa;
    unsigned n;
    unsigned char *bp;

    if (zsoa->zsoa_valid)
      return 1; /* ignore if already set */

    line += 4;
    SKIPSPACE(line);

    if (!(line = parse_ttl_nb(line, zsoa->zsoa_ttl, ds->ds_ttl))) return 0;

    if (!(line = parse_dn(line, zsoa->zsoa_oldn + 1, &n))) return 0;
    zsoa->zsoa_oldn[0] = n;
    if (!(line = parse_dn(line, zsoa->zsoa_pldn + 1, &n))) return 0;
    zsoa->zsoa_pldn[0] = n;

    /* serial */
    bp = zsoa->zsoa_n;
    if (!(line = parse_uint32_nb(line, bp))) return 0;
    /* refresh, retry, expiry, minttl */
    bp += 4;
    for(n = 0; n < 4; ++n) {
      if (!(line = parse_time_nb(line, bp))) return 0;
      bp += 4;
    }

    if (*line) return 0;

    zsoa->zsoa_valid = 1;

    return 1;
  }

  if ((line[0] == 'n' || line[0] == 'N') &&
      (line[1] == 's' || line[1] == 'S') &&
      ISSPACE(line[2])) {

     struct zonens *zns, **znsp;
     unsigned char dn[DNS_MAXDN+1+1];
     unsigned n;

     line += 3;
     SKIPSPACE(line);

     if (!(line = parse_ttl_nb(line, dn, ds->ds_ttl))) return 0;

     if (!(line = parse_dn(line, dn + 5, &n))) return 0;
     dn[4] = (unsigned char)n;
     n += 4;

     zns = (struct zonens*)mp_alloc(ds->ds_mp, sizeof(struct zonens) + n, 1);
     if (!zns) return 0;
     memcpy(zns->zns_ttlldn, dn, n + 1);

     znsp = &ds->ds_zns;
     while(*znsp) znsp = &(*znsp)->zns_next;
     *znsp = zns;
     zns->zns_next = NULL;

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
  ds->ds_zsoa.zsoa_valid = 0;
  memcpy(ds->ds_ttl, defttl, 4);
  ds->ds_zns = NULL;
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
  const struct zonesoa *zsoa = NULL;
  const struct zonens *zns;
  const unsigned char **nsp = zone->z_zttllns;
  unsigned n;
  struct dslist *dsl;

  zone->z_nns = 0;

  for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next) {
    const struct dataset *ds = dsl->dsl_ds;
    if (!ds->ds_stamp)
      return 0;
    if (stamp < ds->ds_stamp)
      stamp = ds->ds_stamp;
    if (!zsoa && ds->ds_zsoa.zsoa_valid)
      zsoa = &ds->ds_zsoa;
    for(zns = ds->ds_zns; zns; zns = zns->zns_next) {
      for(n = 0; ; ++n) {
        if (n == zone->z_nns) {
          if (n < sizeof(zone->z_zttllns) / sizeof(zone->z_zttllns[0]))
            nsp[zone->z_nns++] = zns->zns_ttlldn;
          break;
        }
        if (zns->zns_ttlldn[4] == nsp[n][4] &&
            memcmp(zns->zns_ttlldn + 4, nsp[n] + 4, nsp[n][4]) == 0)
          break;
      }
    }
  }
  zone->z_stamp = stamp;
  if (zsoa) {
    unsigned char *ser;
    zone->z_zsoa = *zsoa;
    ser = zone->z_zsoa.zsoa_n;	/* serial # */
    if (memcmp(ser, "\0\0\0\0", 4) == 0) /* it is 0, set it to stamp */
      PACK32(ser, stamp);
  }
  else
    zone->z_zsoa.zsoa_valid = 0;

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
        dslog(LOG_WARNING, 0,
              "partially loaded zone %.60s will not be serviced", name);
        zonelist->z_stamp = 0;
        zonelist->z_zsoa.zsoa_valid = 0;
        zonelist->z_nns = 0;
      }
    }

  }

  return errors ? -1 : reloaded ? 1 : 0;
}

void dumpzone(const struct zone *z, FILE *f) {
  const struct dslist *dsl;
  { /* zone header */
    char name[DNS_MAXDOMAIN+1];
    const struct zonesoa *zsoa = &z->z_zsoa;
    const unsigned char **zns = z->z_zttllns;
    unsigned nns = z->z_nns;
    dns_dntop(z->z_dn, name, sizeof(name));
    fprintf(f, "$ORIGIN\t%s.\n", name);
    if (zsoa->zsoa_valid) {
      fprintf(f, "@\t%u\tSOA", unpack32(zsoa->zsoa_ttl));
      dns_dntop(zsoa->zsoa_oldn + 1, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      dns_dntop(zsoa->zsoa_pldn + 1, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      fprintf(f, "\t(%u %u %u %u %u)\n",
          unpack32(zsoa->zsoa_n+0),
          unpack32(zsoa->zsoa_n+4),
          unpack32(zsoa->zsoa_n+8),
          unpack32(zsoa->zsoa_n+12),
          unpack32(zsoa->zsoa_n+16));
    }
    while(nns--) {
      dns_dntop(*zns + 5, name, sizeof(name));
      fprintf(f, "\t%u\tNS\t%s.\n", unpack32(*zns++), name);
    }
  }
  for (dsl = z->z_dsl; dsl; dsl = dsl->dsl_next) {
    fprintf(f, "$TTL %u\n", unpack32(dsl->dsl_ds->ds_ttl));
    dsl->dsl_ds->ds_type->dst_dumpfn(dsl->dsl_ds, z->z_dn, f);
  }
}
