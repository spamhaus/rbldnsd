/* $Id$
 * Nameserver zones: structures and routines
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef PRINT_TIMES
#include <sys/times.h>
#endif
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>

#include "dns.h"
#include "rbldnsd.h"
#include "rbldnsd_zones.h"

/* a list of zonetypes. */
static const struct zonetype *zonetypes[] = {
  &ip4vset_zone,
  &ip4set_zone,
  &dnvset_zone,
  &dnset_zone,
  &generic_zone
};

static struct zonedataset *zonedatasets;

static struct {
  const struct zonedataset *zd;
  const char *fname;
  int warns;
} curloading;

void printzonetypes(FILE *f) {
  unsigned i;
  for (i = 0; i < sizeof(zonetypes)/sizeof(zonetypes[0]); ++i)
    fprintf(f, " %s %s\n", zonetypes[i]->name, zonetypes[i]->descr);
}

static void
vzlog(int level, int lineno, const char *fmt, va_list ap) {
  char buf[1024];
  int pl, l;
  l = pl = (logto & LOGTO_STDOUT) ?
       ssprintf(buf, sizeof(buf), "%.30s: ", progname) : 0;
  if (curloading.zd) {
    l += ssprintf(buf + l, sizeof(buf) - l, "%s:%.50s: ",
                  curloading.zd->type->name, curloading.zd->spec);
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

void zlog(int level, int lineno, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vzlog(level, lineno, fmt, ap);
  va_end(ap);
}

#define MAXWARN 5

void zwarn(int lineno, const char *fmt, ...) {
  if (++curloading.warns <= MAXWARN) { /* prevent syslog flood */
    va_list ap;
    va_start(ap, fmt);
    zlog(LOG_WARNING, lineno, fmt, ap);
    va_end(ap);
  }
}

void zloaded(const char *fmt, ...) {
  char buf[128];
  va_list ap;
  struct tm *tm = gmtime(&curloading.zd->stamp);
  if (curloading.warns > MAXWARN)
    zlog(LOG_WARNING, 0, "%d more warnings suppressed",
         curloading.warns - MAXWARN);
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  zlog(LOG_INFO, 0, "%04d-%02d-%02d %02d:%02d:%02d: %s",
       tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
       tm->tm_hour, tm->tm_min, tm->tm_sec,
       buf);
}

static struct zonedataset *newzonedataset(char *spec) {
  /* type:file,file,file... */
  struct zonedataset *z;
  char *f;
  struct zonefile **zfp, *zf;
  static const char *const delims = ",:";
  unsigned n;

  f = strchr(spec, ':');
  if (!f)
    error(0, "invalid zone data specification `%.60s'", spec);
  *f++ = '\0';

  for(z = zonedatasets; z; z = z->next)
    if (strcmp(z->type->name, spec) == 0 && strcmp(z->spec, f) == 0)
      return z;

  z = (struct zonedataset *)emalloc(sizeof(*z));
  memset(z, 0, sizeof(*z));
  z->next = zonedatasets;
  zonedatasets = z;
  z->spec = estrdup(f);

  n = 0;
  while(strcmp(spec, zonetypes[n]->name))
    if (++n >= sizeof(zonetypes)/sizeof(zonetypes[0]))
      error(0, "unknown zone type `%.60s'", spec);
  z->type = zonetypes[n];
  z->queryfn = z->type->queryfn;
  z->qfilter = z->type->qfilter;

  for(zfp = &z->file, f = strtok(f, delims); f; f = strtok(NULL, delims)) {
    zf = (struct zonefile *)emalloc(sizeof(*zf));
    zf->stamp = 0;
    zf->name = estrdup(f);
    *zfp = zf;
    zfp = &zf->next;
  }
  *zfp = NULL;
  if (!z->file)
    error(0, "missing filenames for %s", spec);

  return z;
}

struct zone *addzone(struct zone *zlist, const char *spec) {
  struct zone *z, **zp;
  struct zonedatalist *zd, **zdp;
  char *p;
  char name[DNS_MAXDOMAIN+1];
  unsigned char dn[DNS_MAXDN];
  unsigned dnlen;

  p = strchr(spec, ':');
  if (!p || p - spec > DNS_MAXDOMAIN)
    error(0, "invalid zone spec `%.60s'", spec);

  memcpy(name, spec, p - spec);
  name[p - spec] = '\0';

  dnlen = dns_ptodn(name, dn, sizeof(dn));
  if (!dnlen)
    error(0, "invalid domain name `%s'", name);
  dns_dntol(dn, dn);

  zp = &zlist;
  for (;;) {
    if (!(z = *zp)) {
      *zp = z = (struct zone *)emalloc(sizeof(*z));
      memset(z, 0, sizeof(*z));
      z->dn = (unsigned char *)emalloc(dnlen);
      memcpy(z->dn, dn, dnlen);
      z->dnlen = dnlen;
      dns_dntop(dn, name, sizeof(name));
      z->name = estrdup(name);
      strcpy(z->name, name);
      break;
    }
    else if (z->dnlen == dnlen && memcmp(z->dn, dn, dnlen) == 0)
      break;
    else
      zp = &z->next;
  }

  zdp = &z->dlist;
  while(*zdp)
    zdp = &(*zdp)->next;

  zd = *zdp = emalloc(sizeof(*zd));
  zd->next = NULL;
  p = estrdup(p+1);
  zd->set = newzonedataset(p);
  free(p);

  return zlist;
}

static int loadzonedata(struct zonedataset *z) {
  struct zonefile *zf;
  time_t stamp = 0;
  FILE *f;

  if (z->data)
    z->type->freefn(z->data);

  z->data = z->type->allocfn();
  if (!z->data)
    return 0;
  for(zf = z->file; zf; zf = zf->next) {
    curloading.fname = zf->name;
    f = fopen(zf->name, "r");
    if (!f) {
      zlog(LOG_ERR, 0, "unable to open file: %s", strerror(errno));
      return 0;
    }
    if (!z->type->loadfn(z->data, f)) {
      fclose(f);
      return 0;
    }
    if (ferror(f)) {
      zlog(LOG_ERR, 0, "error reading file `%.60s': %s",
           zf->name, strerror(errno));
      fclose(f);
      return 0;
    }
    fclose(f);
    if (zf->stamp > stamp)
      stamp = zf->stamp;
  }
  curloading.fname = NULL;
  z->stamp = stamp;

  if (!z->type->finishfn(z->data))
    return 0;

  return 1;
}

int reloadzones(struct zone *zl) {
  struct zonedataset *zd;
  struct zonefile *zf;
  struct zonedatalist *zdl;
  int reloaded = 0;
  int errors = 0;
#ifdef PRINT_TIMES
  struct tms tms;
  clock_t utm, etm;

  etm = times(&tms);
  utm = tms.tms_utime;
#endif

  for(zd = zonedatasets; zd; zd = zd->next) {
    int load = 0;

    memset(&curloading, 0, sizeof(curloading));
    curloading.zd = zd;

    for(zf = zd->file; zf; zf = zf->next) {
      struct stat st;
      if (stat(zf->name, &st) < 0) {
        zlog(LOG_ERR, 0, "unable to stat file `%.60s': %s",
             zf->name, strerror(errno));
        load = -1;
        break;
      }
      else if (zf->stamp != st.st_mtime) {
        load = 1;
        zf->stamp = st.st_mtime;
      }
    }

    if (!load)
      continue;

    ++reloaded;

    if (load < 0 || !loadzonedata(zd)) {
      ++errors;
      for (zf = zd->file; zf; zf = zf->next)
        zf->stamp = 0;
      if (zd->data) {
        zd->type->freefn(zd->data);
        zd->data = NULL;
      }
      zd->stamp = 0;
    }

  }

  curloading.zd = NULL;

  if (reloaded) {

    while(zl) {
      for(zdl = zl->dlist; zdl; zdl = zdl->next)
	if (!zdl->set->stamp)
	  break;
      if (zdl) {
	zlog(LOG_WARNING, 0,
	     "partially loaded zone %.60s will not be serviced",
	     zl->name);
	zl->loaded = 0;
      }
      else
	zl->loaded = 1;
      zl = zl->next;
    }

#ifdef PRINT_TIMES
    if (!errors) {
#ifndef HZ
      static clock_t HZ;
      if (!HZ)
        HZ = sysconf(_SC_CLK_TCK);
#endif
      etm = times(&tms) - etm;
      utm = tms.tms_utime - utm;
#define sec(tm) tm/HZ, (etm*100/HZ)%100
      zlog(LOG_INFO, 0, "zones (re)loaded (%lu.%lu/%lu.%lu sec)",
           sec(etm),sec(utm));
    }
#endif

  }

  return errors ? 0 : 1;
}
