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

#include "dns.h"
#include "rbldnsd.h"

/* a list of zonetypes. */
static const struct dataset_type *dataset_types[] = {
  &dataset_ip4vset_type,
  &dataset_ip4set_type,
  &dataset_dnvset_type,
  &dataset_dnset_type,
  &dataset_generic_type
};

static struct zonedataset *zonedatasets;

static struct {
  const struct zonedataset *zds;
  const char *fname;
  int warns;
} curloading;

void printdstypes(FILE *f) {
  unsigned i;
  for (i = 0; i < sizeof(dataset_types)/sizeof(dataset_types[0]); ++i)
    fprintf(f, " %s - %s\n",
            dataset_types[i]->dst_name, dataset_types[i]->dst_descr);
}

static void
vdslog(int level, int lineno, const char *fmt, va_list ap) {
  char buf[1024];
  int pl, l;
  l = pl = (logto & LOGTO_STDOUT) ?
       ssprintf(buf, sizeof(buf), "%.30s: ", progname) : 0;
  if (curloading.zds) {
    l += ssprintf(buf + l, sizeof(buf) - l, "%s:%.50s: ",
                  curloading.zds->zds_type->dst_name, curloading.zds->zds_spec);
    if (curloading.fname) {
      l += ssprintf(buf + l, sizeof(buf) - l, "%.60s",
                    curloading.fname);
      l += ssprintf(buf + l, sizeof(buf) - l,
                    lineno ? "(%d): " : ": ", lineno);
    }
  }
  l += vssprintf(buf + l, sizeof(buf) - l, fmt, ap);
  if (logto & LOGTO_SYSLOG) {
    fmt = buf + pl;
    syslog(level, strchr(fmt, '%') ? "%s" : fmt, fmt);
  }
  if (logto & LOGTO_STDOUT) {
    buf[l++] = '\n';
    write(1, buf, l);
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
  if (++curloading.warns <= MAXWARN) { /* prevent syslog flood */
    va_list ap;
    va_start(ap, fmt);
    dslog(LOG_WARNING, lineno, fmt, ap);
    va_end(ap);
  }
}

void dsloaded(const char *fmt, ...) {
  char buf[128];
  va_list ap;
  struct tm *tm = gmtime(&curloading.zds->zds_stamp);
  if (curloading.warns > MAXWARN)
    dslog(LOG_WARNING, 0, "%d more warnings suppressed",
         curloading.warns - MAXWARN);
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  dslog(LOG_INFO, 0, "%04d%02d%02d %02d%02d%02d: %s",
       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
       tm->tm_hour, tm->tm_min, tm->tm_sec,
       buf);
}

static struct zonedataset *newzonedataset(char *spec) {
  /* type:file,file,file... */
  struct zonedataset *zds;
  char *f;
  struct zonefile **zfp, *zf;
  static const char *const delims = ",:";
  unsigned n;

  f = strchr(spec, ':');
  if (!f)
    error(0, "invalid zone data specification `%.60s'", spec);
  *f++ = '\0';

  for(zds = zonedatasets; zds; zds = zds->zds_next)
    if (strcmp(zds->zds_type->dst_name, spec) == 0 &&
        strcmp(zds->zds_spec, f) == 0)
      return zds;

  zds = tzalloc(struct zonedataset);
  zds->zds_next = zonedatasets;
  zonedatasets = zds;
  zds->zds_spec = estrdup(f);

  n = 0;
  while(strcmp(spec, dataset_types[n]->dst_name))
    if (++n >= sizeof(dataset_types)/sizeof(dataset_types[0]))
      error(0, "unknown zone type `%.60s'", spec);
  zds->zds_type = dataset_types[n];

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

struct zone *addzone(struct zone *zonelist, const char *spec) {
  struct zone *zone, **zonep;
  struct zonedatalist *zdl, **zdlp;
  char *p;
  char name[DNS_MAXDOMAIN];
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;

  p = strchr(spec, ':');
  if (!p || p - spec >= DNS_MAXDOMAIN)
    error(0, "invalid zone spec `%.60s'", spec);

  memcpy(name, spec, p - spec);
  name[p - spec] = '\0';

  dnlen = dns_ptodn(name, dn, DNS_MAXDN);
  if (!dnlen)
    error(0, "invalid domain name `%s'", name);
  dns_dntol(dn, dn);

  zonep = &zonelist;
  for (;;) {
    if (!(zone = *zonep)) {
      *zonep = zone = tzalloc(struct zone);
      zone->z_dn = (unsigned char*)emalloc(dnlen*2+sizeof(int)); /* align */
      zone->z_rdn = zone->z_dn + dnlen;
      memcpy(zone->z_dn, dn, dnlen);
      dns_dnreverse(dn, zone->z_rdn, dnlen);
      zone->z_dnlen = dnlen;
      zone->z_dnlab = dns_dnlabels(dn);
      dns_dntop(dn, name, sizeof(name));
      zone->z_name = estrdup(name);
      strcpy(zone->z_name, name);
      break;
    }
    else if (zone->z_dnlen == dnlen && memcmp(zone->z_dn, dn, dnlen) == 0)
      break;
    else
      zonep = &zone->z_next;
  }

  zdlp = &zone->z_zdl;
  while(*zdlp)
    zdlp = &(*zdlp)->zdl_next;

  zdl = *zdlp = tmalloc(struct zonedatalist);
  zdl->zdl_next = NULL;
  p = estrdup(p+1);
  zdl->zdl_zds = newzonedataset(p);
  free(p);
  zdl->zdl_queryfn = zdl->zdl_zds->zds_type->dst_queryfn;
  zone->z_dstflags |= zdl->zdl_zds->zds_type->dst_flags;

  return zonelist;
}

static int loadzonedataset(struct zonedataset *zds) {
  struct zonefile *zf;
  time_t stamp = 0;
  FILE *f;

  if (zds->zds_ds)
    zds->zds_type->dst_freefn(zds->zds_ds);
  zds->zds_zsoa.zsoa_valid = 0;
  if (!(zds->zds_ds = zds->zds_type->dst_allocfn()))
    return 0;

  for(zf = zds->zds_zf; zf; zf = zf->zf_next) {
    curloading.fname = zf->zf_name;
    f = fopen(zf->zf_name, "r");
    if (!f) {
      dslog(LOG_ERR, 0, "unable to open file: %s", strerror(errno));
      return 0;
    }
    if (!zds->zds_type->dst_loadfn(zds, f)) {
      fclose(f);
      return 0;
    }
    if (ferror(f)) {
      dslog(LOG_ERR, 0, "error reading file `%.60s': %s",
           zf->zf_name, strerror(errno));
      fclose(f);
      return 0;
    }
    fclose(f);
    if (zf->zf_stamp > stamp)
      stamp = zf->zf_stamp;
  }
  curloading.fname = NULL;
  zds->zds_stamp = stamp;

  if (!zds->zds_type->dst_finishfn(zds->zds_ds))
    return 0;

  return 1;
}

int reloadzones(struct zone *zonelist) {
  struct zonedataset *zds;
  struct zonefile *zf;
  struct zonedatalist *zdl;
  struct zone *zone;
  int reloaded = 0;
  int errors = 0;

  for(zds = zonedatasets; zds; zds = zds->zds_next) {
    int load = 0;

    memset(&curloading, 0, sizeof(curloading));
    curloading.zds = zds;

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
      for (zf = zds->zds_zf; zf; zf = zf->zf_next)
        zf->zf_stamp = 0;
      if (zds->zds_ds) {
        zds->zds_type->dst_freefn(zds->zds_ds);
        zds->zds_ds = NULL;
      }
      zds->zds_stamp = 0;
    }

  }

  curloading.zds = NULL;

  if (reloaded) {

    for (zone = zonelist; zone; zone = zone->z_next) {
      time_t stamp = 0;
      struct zonesoa *zsoa = NULL;
      for(zdl = zone->z_zdl; zdl; zdl = zdl->zdl_next) {
        zds = zdl->zdl_zds;
        zdl->zdl_ds = zds->zds_ds;
        if (!zds->zds_stamp)
          break;
        else if (stamp < zds->zds_stamp)
          stamp = zds->zds_stamp;
        if (!zsoa && zds->zds_zsoa.zsoa_valid)
          zsoa = &zds->zds_zsoa;
      }
      if (zdl) {
        dslog(LOG_WARNING, 0,
              "partially loaded zone %.60s will not be serviced",
              zone->z_name);
        zone->z_stamp = 0;
	zone->z_zsoa.zsoa_valid = 0;
        continue;
      }
      zone->z_stamp = stamp;
      if (zsoa) {
        unsigned char *ser;
        zone->z_zsoa = *zsoa;
        ser = zone->z_zsoa.zsoa_n;	/* serial # */
        if (memcmp(ser, "\0\0\0\0", 4) == 0) { /* it is 0, set it to stamp */
          ser[0] = stamp >> 24; ser[1] = stamp >> 16;
          ser[2] = stamp >> 8; ser[3] = stamp;
        }
      }
      else
        zone->z_zsoa.zsoa_valid = 0;
    }

  }

  return errors ? -1 : reloaded ? 1 : 0;
}
