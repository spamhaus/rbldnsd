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

static struct zonedataset *zonedatasets;

struct zonedataset *zds_loading;

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
  if (zds_loading) {
    l += ssprintf(buf + l, sizeof(buf) - l, "%s:%.60s:",
                  zds_loading->zds_type->dst_name, zds_loading->zds_spec);
    if (zds_loading->zds_subset)
      l += ssprintf(buf + l, sizeof(buf) - l, "%s:",
                    zds_loading->zds_subset->zds_type->dst_name);
    if (zds_loading->zds_fname) {
      l += ssprintf(buf + l, sizeof(buf) - l, " %.60s",
                    zds_loading->zds_fname);
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
  if (++zds_loading->zds_warn <= MAXWARN) { /* prevent syslog flood */
    va_list ap;
    va_start(ap, fmt);
    dslog(LOG_WARNING, lineno, fmt, ap);
    va_end(ap);
  }
}

void dsloaded(const char *fmt, ...) {
  va_list ap;
  zds_loading->zds_fname = NULL;
  if (zds_loading->zds_warn > MAXWARN)
    dslog(LOG_WARNING, 0, "%d more warnings suppressed",
          zds_loading->zds_warn - MAXWARN);
  va_start(ap, fmt);
  if (zds_loading->zds_subset)
     vdslog(LOG_INFO, 0, fmt, ap);
  else {
    struct tm *tm = gmtime(&zds_loading->zds_stamp);
    char buf[128];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    dslog(LOG_INFO, 0, "%04d%02d%02d %02d%02d%02d: %s",
          tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
          tm->tm_hour, tm->tm_min, tm->tm_sec,
          buf);
  }
  va_end(ap);
}

static struct zonedataset *newzonedataset(char *spec) {
  /* type:file,file,file... */
  struct zonedataset *zds;
  char *f;
  struct zonefile **zfp, *zf;
  static const char *const delims = ",:";
  const struct dataset_type **dstp;

  f = strchr(spec, ':');
  if (!f)
    error(0, "invalid zone data specification `%.60s'", spec);
  *f++ = '\0';

  for(zds = zonedatasets; zds; zds = zds->zds_next)
    if (strcmp(zds->zds_type->dst_name, spec) == 0 &&
        strcmp(zds->zds_spec, f) == 0)
      return zds;

  dstp = dataset_types;
  while(strcmp(spec, (*dstp)->dst_name))
    if (!*++dstp)
      error(0, "unknown dataset type `%.60s'", spec);
  zds = (struct zonedataset*)ezalloc(sizeof(struct zonedataset) +
                                     (*dstp)->dst_size);
  zds->zds_type = *dstp;
  zds->zds_ds = (struct dataset*)(zds + 1);
  zds->zds_spec = estrdup(f);

  zds->zds_next = zonedatasets;
  zonedatasets = zds;

  for(zfp = &zds->zds_zf, f = strtok(f, delims); f; f = strtok(NULL, delims)) {
    zf = tmalloc(struct zonefile);
    zf->zf_stamp = 0;
    zf->zf_name = estrdup(f);
    *zfp = zf;
    zfp = &zf->zf_next;
  }
  *zfp = NULL;
  if (!zds->zds_zf)
    error(0, "missing filenames for %s", spec);

  return zds;
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
        zone = (struct zone *)mp_alloc(mp, sizeof(*zone));
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
      zone->z_zdlp = &zone->z_zdl;
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

void connectzonedataset(struct zone *zone,
                        struct zonedataset *zds,
                        struct zonedatalist *zdl) {
  zdl->zdl_next = NULL;
  *zone->z_zdlp = zdl;
  zone->z_zdlp = &zdl->zdl_next;
  zdl->zdl_zds = zds;
  zdl->zdl_queryfn = zds->zds_type->dst_queryfn;
  zone->z_dstflags |= zds->zds_type->dst_flags;
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
  connectzonedataset(zone, newzonedataset(p), tmalloc(struct zonedatalist));
  free(p);

  return zonelist;
}

/* parse $SPECIAL construct */
int zds_special(struct zonedataset *zds, char *line, int lineno) {

  if ((line[0] == 's' || line[0] == 'S') &&
      (line[1] == 'o' || line[1] == 'O') &&
      (line[2] == 'a' || line[2] == 'A') &&
      ISSPACE(line[3])) {

    /* SOA record */
    struct zonesoa *zsoa = &zds->zds_zsoa;
    unsigned n;
    unsigned char *bp;

    if (zsoa->zsoa_valid)
      return 1; /* ignore if already set */

    line += 4;
    SKIPSPACE(line);

    if (!(line = parse_ttl_nb(line, zsoa->zsoa_ttl, zds->zds_ttl))) return 0;

    if (!(line = parse_dn(line, zsoa->zsoa_odn + 1, &n))) return 0;
    zsoa->zsoa_odn[0] = n;
    if (!(line = parse_dn(line, zsoa->zsoa_pdn + 1, &n))) return 0;
    zsoa->zsoa_pdn[0] = n;

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

     if (!(line = parse_ttl_nb(line, dn, zds->zds_ttl))) return 0;

     if (!(line = parse_dn(line, dn + 5, &n))) return 0;
     dn[4] = (unsigned char)n;
     n += 5;

     zns = (struct zonens *)mp_alloc(&zds->zds_mp, sizeof(struct zonens) + n);
     if (!zns) return 0;
     zns->zns_dn = (unsigned char*)(zns + 1);
     memcpy(zns->zns_dn, dn, n);

     znsp = &zds->zds_zns;
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
    if (zds->zds_subset) zds = zds->zds_subset;
    memcpy(zds->zds_ttl, ttl, 4);
    return 1;
  }

  if (line[0] >= '0' && line[0] <= '9' &&
      ISSPACE(line[1])) {
    /* substitution vars */
    unsigned n = line[0] - '0';
    if (zds->zds_subset) zds = zds->zds_subset;
    if (zds->zds_subst[n]) return 1; /* ignore second assignment */
    line += 2;
    SKIPSPACE(line);
    if (!*line) return 0;
    if (!(zds->zds_subst[n] = estrdup(line))) return 0;
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
      zds->zds_type == &dataset_combined_type) {
    line += 8;
    SKIPSPACE(line);
    return ds_combined_newset(zds, line, lineno);
  }

  return 0;
}

static void freezonedataset(struct zonedataset *zds) {
  zds->zds_type->dst_resetfn(zds->zds_ds);
  mp_free(&zds->zds_mp);
  zds->zds_zsoa.zsoa_valid = 0;
  memcpy(zds->zds_ttl, defttl, 4);
  zds->zds_zns = NULL;
  memset(zds->zds_subst, 0, sizeof(zds->zds_subst));
  zds->zds_warn = 0;
  zds->zds_subset = NULL;
}

static int loadzonedataset(struct zonedataset *zds) {
  struct zonefile *zf;
  time_t stamp = 0;
  FILE *f;

  freezonedataset(zds);

  zds_loading = zds;

  for(zf = zds->zds_zf; zf; zf = zf->zf_next) {
    zds->zds_fname = zf->zf_name;
    f = fopen(zf->zf_name, "r");
    if (!f) {
      dslog(LOG_ERR, 0, "unable to open file: %s", strerror(errno));
      return 0;
    }
    zds->zds_type->dst_startfn(zds);
    if (!readdslines(f, zds)) {
      fclose(f);
      return 0;
    }
    if (ferror(f)) {
      dslog(LOG_ERR, 0, "error reading file: %s", strerror(errno));
      fclose(f);
      return 0;
    }
    fclose(f);
    if (zf->zf_stamp > stamp)
      stamp = zf->zf_stamp;
  }
  zds->zds_fname = NULL;
  zds->zds_stamp = stamp;

  zds->zds_type->dst_finishfn(zds);

  zds_loading = NULL;

  return 1;
}

static int updatezone(struct zone *zone) {
  time_t stamp = 0;
  const struct zonesoa *zsoa = NULL;
  const struct zonens *zns;
  const unsigned char **nsp = zone->z_zns;
  unsigned n;
  struct zonedatalist *zdl;

  zone->z_nns = 0;

  for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next) {
    const struct zonedataset *zds = zdl->zdl_zds;
    if (!zds->zds_stamp)
      return 0;
    if (stamp < zds->zds_stamp)
      stamp = zds->zds_stamp;
    if (!zsoa && zds->zds_zsoa.zsoa_valid)
      zsoa = &zds->zds_zsoa;
    for(zns = zds->zds_zns; zns; zns = zns->zns_next) {
      for(n = 0; ; ++n) {
        if (n == zone->z_nns) {
          if (n < sizeof(zone->z_zns) / sizeof(zone->z_zns[0]))
            nsp[zone->z_nns++] = zns->zns_dn;
          break;
        }
        if (zns->zns_dn[4] == nsp[n][4] &&
            memcmp(zns->zns_dn + 4, nsp[n] + 4, nsp[n][4]) == 0)
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
  struct zonedataset *zds;
  struct zonefile *zf;
  int reloaded = 0;
  int errors = 0;

  for(zds = zonedatasets; zds; zds = zds->zds_next) {
    int load = 0;

    zds_loading = zds;

    for(zf = zds->zds_zf; zf; zf = zf->zf_next) {
      struct stat st;
      if (stat(zf->zf_name, &st) < 0) {
        dslog(LOG_ERR, 0, "unable to stat file `%.60s': %s",
             zf->zf_name, strerror(errno));
        load = -1;
        break;
      }
      else if (zf->zf_stamp != st.st_mtime) {
        load = 1;
        zf->zf_stamp = st.st_mtime;
      }
    }

    if (!load)
      continue;

    ++reloaded;

    if (load < 0 || !loadzonedataset(zds)) {
      ++errors;
      freezonedataset(zds);
      for (zf = zds->zds_zf; zf; zf = zf->zf_next)
        zf->zf_stamp = 0;
      zds->zds_stamp = 0;
    }

  }

  zds_loading = NULL;

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
  const struct zonedatalist *zdl;
  { /* zone header */
    char name[DNS_MAXDOMAIN+1];
    const struct zonesoa *zsoa = &z->z_zsoa;
    const unsigned char **zns = z->z_zns;
    unsigned nns = z->z_nns;
    dns_dntop(z->z_dn, name, sizeof(name));
    fprintf(f, "$ORIGIN\t%s.\n", name);
    if (zsoa->zsoa_valid) {
      fprintf(f, "@\t%u\tSOA", unpack32(zsoa->zsoa_ttl));
      dns_dntop(zsoa->zsoa_odn + 1, name, sizeof(name));
      fprintf(f, "\t%s.", name);
      dns_dntop(zsoa->zsoa_pdn + 1, name, sizeof(name));
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
  for (zdl = z->z_zdl; zdl; zdl = zdl->zdl_next) {
    fprintf(f, "$TTL %u\n", unpack32(zdl->zdl_zds->zds_ttl));
    zdl->zdl_zds->zds_type->dst_dumpfn(zdl->zdl_zds, z->z_dn, f);
  }
}
