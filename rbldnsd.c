/* $Id$
 * rbldnsd: main program
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <fcntl.h>
#ifndef NOMEMINFO
# include <malloc.h>
#endif
#ifndef NOTIMES
# include <sys/times.h>
#endif

#include "rbldnsd.h"

#ifndef NI_WITHSCOPEID
# define NI_WITHSCOPEID 0
#endif
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif

const char *version = VERSION;
char *progname; /* limited to 32 chars */
int logto;

void error(int errnum, const char *fmt, ...) {
  char buf[256];
  int l, pl;
  va_list ap;
  l = pl = ssprintf(buf, sizeof(buf), "%.30s: ", progname);
  va_start(ap, fmt);
  l += vssprintf(buf + l, sizeof(buf) - l, fmt, ap);
  if (errnum)
    l += ssprintf(buf + l, sizeof(buf) - l, ": %.50s", strerror(errnum));
  if (logto & LOGTO_SYSLOG) {
    fmt = buf + pl;
    syslog(LOG_ERR, strchr(fmt, '%') ? "%s" : fmt, fmt);
  }
  buf[l++] = '\n';
  write(2, buf, l);
  _exit(1);
}

static unsigned recheck = 60;	/* interval between checks for reload */
static int accept_in_cidr;	/* accept 127.0.0.1/8-style CIDRs */
static int initialized;		/* 1 when initialized */
static char *logfile;		/* log file name */
static int logmemtms;		/* print memory usage and (re)load time info */
unsigned char defttl[4] = "\0\0\010\064";	/* default record TTL 35m */
const char def_rr[5] = "\177\0\0\2\0";		/* default A RR */
struct dataset *ds_loading;

/* a list of zonetypes. */
const struct dstype *ds_types[] = {
  &dataset_ip4set_type,
  &dataset_dnset_type,
#ifdef DNHASH
  &dataset_dnhash_type,
#endif
  &dataset_generic_type,
  &dataset_combined_type,
  NULL
};

static int satoi(const char *s) {
  int n = 0;
  if (*s < '0' || *s > '9') return -1;
  do n = n * 10 + (*s++ - '0');
  while (*s >= '0' && *s <= '9');
  return *s ? -1 : n;
}

#ifndef NOMEMINFO
static void logmemusage() {
  if (logmemtms) {
    struct mallinfo mi = mallinfo();
    dslog(LOG_INFO, 0,
       "memory usage: "
       "arena=%d/%d ord=%d free=%d keepcost=%d mmaps=%d/%d",
       mi.arena, mi.ordblks, mi.uordblks, mi.fordblks, mi.keepcost,
       mi.hblkhd, mi.hblks);
  }
}
#else
# define logmemusage()
#endif

static int do_reload(struct zone *zonelist) {
  int r;
#ifndef NOTIMES
  struct tms tms;
  clock_t utm, etm;
#ifndef HZ
  static clock_t HZ;
  if (!HZ)
    HZ = sysconf(_SC_CLK_TCK);
#endif
  etm = times(&tms);
  utm = tms.tms_utime;
#endif

  r = reloadzones(zonelist);
  if (!r)
    return 1;

#ifndef NOTIMES
  if (logmemtms) {
    etm = times(&tms) - etm;
    utm = tms.tms_utime - utm;
#define sec(tm) tm/HZ, (etm*100/HZ)%100
    dslog(LOG_INFO, 0, "zones (re)loaded: %lu.%lue/%lu.%luu sec",
         sec(etm), sec(utm));
#undef sec
  }
#endif
  logmemusage();
  return r < 0 ? 0 : 1;
}

static void NORETURN usage(int exitcode) {
   const struct dstype **dstp;
   printf(
"%s: rbl dns daemon version %s\n"
"Usage is: %s [options] zonespec...\n"
"where options are:\n"
" -u user[:group] - run as this user:group (rbldns)\n"
" -r rootdir - chroot to this directory\n"
" -w workdir - working directory with zone files\n"
" -b address - bind to (listen on) this address\n"
" -P port - listen on this port\n"
#ifndef NOIPv6
" -4 - use IPv4 socket type\n"
" -6 - use IPv6 socket type\n"
#endif
" -t ttl - TTL value set in answers (35m)\n"
" -e - enable CIDR ranges where prefix is not on the range boundary\n"
"  (by default ranges such 127.0.0.1/8 will be rejected)\n"
" -c check - time interval to check for file updates (1m)\n"
" -p pidfile - write backgrounded pid to specified file\n"
" -n - do not become a daemon\n"
" -q - quickstart, load zones after backgrounding\n"
" -l logfile - log queries and answers to this file\n"
"  (relative to chroot directory)\n"
" -s - print memory usage and (re)load time info on zone reloads\n"
" -d - dump all zones in BIND format to standard output and exit\n"
"each zone specified using `name:type:file,file...'\n"
"syntax, repeated names constitute the same zone.\n"
"Available dataset types:\n"
, progname, version, progname);
  for(dstp = ds_types; *dstp; ++dstp)
    printf(" %s - %s\n", (*dstp)->dst_name, (*dstp)->dst_descr);
  exit(exitcode);
}

static volatile int signalled;
#define SIGNALLED_RELOAD	0x01
#define SIGNALLED_RELOG		0x02
#define SIGNALLED_STATS		0x04
#define SIGNALLED_ZEROSTATS	0x08
#define SIGNALLED_TERM		0x10

static int init(int argc, char **argv, struct zone **zonep) {
  int c;
  char *p;
  char *user = NULL, *bindaddr = NULL, *port = "domain";
  char *rootdir = NULL, *workdir = NULL, *pidfile = NULL;
  FILE *fpid = NULL;
  uid_t uid = 0;
  gid_t gid = 0;
  int fd;
  int nodaemon = 0, quickstart = 0, dump = 0;
#ifndef NOIPv6
  struct addrinfo hints, *aires, *ai;
  char host[NI_MAXHOST], serv[NI_MAXSERV];
#else
  struct sockaddr_in sin;
  ip4addr_t sinaddr;
#endif

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  if (argc <= 1) usage(1);

#ifndef NOIPv6
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;
#endif

  while((c = getopt(argc, argv, "u:r:b:P:w:t:c:p:nel:qsh46d")) != EOF)
    switch(c) {
    case 'u': user = optarg; break;
    case 'r': rootdir = optarg; break;
    case 'b': bindaddr = optarg; break;
    case 'P': port = optarg; break;
#ifndef NOIPv6
    case '4': hints.ai_family = AF_INET; break;
    case '6': hints.ai_family = AF_INET6; break;
#else
    case '4': break;
    case '6': error(0, "IPv6 support isn't compiled in");
#endif
    case 'w': workdir = optarg; break;
    case 'p': pidfile = optarg; break;
    case 't':
      if (!(p = parse_time_nb(optarg, defttl)) || *p)
        error(0, "invalid ttl (-t) value `%.50s'", optarg);
      break;
    case 'c':
      if (!(p = parse_time(optarg, &recheck)) || *p)
        error(0, "invalid check interval (-c) value `%.50s'", optarg);
      break;
    case 'n': nodaemon = 1; break;
    case 'e': accept_in_cidr = 1; break;
    case 'l': logfile = optarg; break;
    case 's': logmemtms = 1; break;
    case 'q': quickstart = 1; break;
    case 'd': dump = 1; break;
    case 'h': usage(0);
    default: error(0, "type `%.50s -h' for help", progname);
    }

  if (!(argc -= optind))
    error(0, "no zone(s) to service specified (-h for help)");
  argv += optind;

  if (dump) {
    struct zone *z;
    time_t now;
    logto = LOGTO_STDERR;
    for(c = 0; c < argc; ++c)
      *zonep = addzone(*zonep, argv[c]);
    if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
      error(errno, "unable to chroot to %.50s", rootdir);
    if (workdir && chdir(workdir) < 0)
      error(errno, "unable to chdir to %.50s", workdir);
    if (!do_reload(*zonep))
      error(0, "zone loading errors, aborting");
    now = time(NULL);
    printf("; zone dump made %s", ctime(&now));
    printf("; rbldnsd version %s\n", version);
    for (z = *zonep; z; z = z->z_next)
      dumpzone(z, stdout);
    fflush(stdout);
    exit(ferror(stdout) ? 1 : 0);
  }

  if (nodaemon)
    logto = LOGTO_STDOUT;
  else {
    tzset();
    openlog(progname, LOG_PID|LOG_NDELAY, LOG_DAEMON);
    logto = LOGTO_STDOUT | LOGTO_SYSLOG;
  }

#ifndef NOIPv6
  c = getaddrinfo(bindaddr, port, &hints, &aires);
  if (!bindaddr) bindaddr = "*";
  if (c != 0)
    error(0, "%s/%s: %s", bindaddr, port, gai_strerror(c));
  for(ai = aires, errno = 0, fd = -1; ai; ai = ai->ai_next)
    if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)
      if ((fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) >= 0)
        break;
  if (fd < 0)
    error(errno, "%s/%s: no available protocols", bindaddr, port);
  getnameinfo(ai->ai_addr, ai->ai_addrlen,
              host, sizeof(host),
              serv, sizeof(serv),
              NI_NUMERICHOST|NI_WITHSCOPEID|NI_NUMERICSERV);
  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
    error(errno, "unable to bind to [%s]/%s", host, serv);
  freeaddrinfo(aires);
#else	/* NOIPv6 */
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  if ((c = satoi(port)) < 0 || c > 0xffff) {
    struct servent *se = getservbyname(port, "udp");
    if (!se)
      error(0, "unknown service %.50s/udp", port);
    sin.sin_port = se->s_port;
    endservent();
  }
  else
    sin.sin_port = htons(c);
  if (bindaddr) {
    if (!ip4addr(bindaddr, &sinaddr, NULL)) {
      struct hostent *he = gethostbyname(bindaddr);
      if (!he
          || he->h_addrtype != AF_INET
          || he->h_length != 4
          || !he->h_addr_list[0])
        error(0, "%.50s: unknown host", bindaddr);
      memcpy(&sin.sin_addr, he->h_addr_list[0], 4);
      sinaddr = ntohl(sin.sin_addr.s_addr);
      endhostent();
    }
    else
      sin.sin_addr.s_addr = htonl(sinaddr);
  }
  else
    sinaddr = 0;
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    error(errno, "unable to create listening socket");
  if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    error(errno, "unable to bind to [%s]:%d",
          ip4atos(sinaddr), ntohs(sin.sin_port));
#endif

  c = 65536;
  do
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &c, sizeof c) == 0)
      break;
  while ((c -= (c >> 5)) >= 1024);

  if (!user && !(uid = getuid()))
    user = "rbldns";

  if (user && (p = strchr(user, ':')) != NULL)
    *p++ = '\0';
  if (!user)
    p = NULL;
  else if ((c = satoi(user)) >= 0)
    uid = c, gid = c;
  else {
    struct passwd *pw = getpwnam(user);
    if (!pw)
      error(0, "unknown user `%s'", user);
    uid = pw->pw_uid;
    gid = pw->pw_gid;
    endpwent();
  }
  if (!uid)
    error(0, "daemon should not run as root, specify -u option");
  if (p) {
    if ((c = satoi(p)) >= 0)
      gid = c;
    else {
      struct group *gr = getgrnam(p);
      if (!gr)
        error(0, "unknown group `%s'", p);
      gid = gr->gr_gid;
      endgrent();
    }
    p[-1] = ':';
  }

  if (pidfile && (fpid = fopen(pidfile, "w")) == NULL)
    error(errno, "unable to write pidfile");

  if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
    error(errno, "unable to chroot to %.50s", rootdir);
  if (workdir && chdir(workdir) < 0)
    error(errno, "unable to chdir to %.50s", workdir);

  if (user)
    if (setgroups(1, &gid) < 0 || setgid(gid) < 0 || setuid(uid) < 0)
      error(errno, "unable to setuid(%d:%d)", uid, gid);

  for(c = 0; c < argc; ++c)
    *zonep = addzone(*zonep, argv[c]);

#ifndef NOIPv6
#define logstarted() \
  dslog(LOG_INFO, 0, "version %s started (listening on [%s]:%s)", \
        version, host, serv)
#else
#define logstarted() \
  dslog(LOG_INFO, 0, "version %s started (listening on [%s]:%d)", \
        version, ip4atos(sinaddr), ntohs(sin.sin_port))
#endif
  if (quickstart)
    signalled = SIGNALLED_RELOAD;	/* zones will be loaded after fork */
  else if (!do_reload(*zonep))
    error(0, "zone loading errors, aborting");
  else
    logstarted();

  initialized = 1;

  if (!nodaemon) {
    if (fork() > 0) exit(0);
    close(0); close(1); close(2);
    setsid();
    logto = LOGTO_SYSLOG;
  }
  if (fpid) {
    fprintf(fpid, "%lu\n", (unsigned long)getpid());
    fclose(fpid);
  }

  if (quickstart)
    logstarted();

  return fd;
}

static void sighandler(int sig) {
  switch(sig) {
  case SIGHUP:
    signalled |= SIGNALLED_RELOG|SIGNALLED_RELOAD;
    break;
  case SIGALRM:
    alarm(recheck);
    signalled |= SIGNALLED_RELOAD;
    break;
  case SIGUSR1:
    signalled |= SIGNALLED_STATS;
    break;
  case SIGUSR2:
    signalled |= SIGNALLED_STATS|SIGNALLED_ZEROSTATS;
    break;
  case SIGTERM:
  case SIGINT:
    signalled |= SIGNALLED_TERM;
    break;
  }
}

static sigset_t ssblock; /* signals to block during zone reload */

static void setup_signals() {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sighandler;
  sigemptyset(&ssblock);
  sigaction(SIGHUP, &sa, NULL);
  sigaddset(&ssblock, SIGHUP);
  sigaction(SIGALRM, &sa, NULL);
  sigaddset(&ssblock, SIGALRM);
#ifndef NOSTATS
  sigaction(SIGUSR1, &sa, NULL);
  sigaddset(&ssblock, SIGUSR1);
  sigaction(SIGUSR2, &sa, NULL);
  sigaddset(&ssblock, SIGUSR2);
#endif
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);	/* in case logfile is FIFO */
}

#ifndef NOSTATS
struct sdnsstats {
  time_t stime;		/* start time */
  dnscnt_t nbad, ibad;	/* unrecognized, short etc requests */
};

static void logstats(struct sdnsstats *s, struct zone *zone, int reset) {
  time_t t = time(NULL);
  time_t d = t - s->stime;
  struct dnsstats tot;
  char name[DNS_MAXDOMAIN+1];
  struct zone *z;
  memset(&tot, 0, sizeof(tot));
  for (z = zone; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(nnxd); add(inxd); add(onxd);
    add(nrep); add(irep); add(orep); add(arep);
    add(nerr); add(ierr); add(oerr);
#undef add
  }
#ifdef STATS_LL
# define C "llu"
#else
# define C "lu"
#endif
  dslog(LOG_INFO, 0,
    "stats for %ldsec (num/in/out/ans): "
    "tot=%" C "/%" C "/%" C "/%" C " "
    "ok=%" C "/%" C "/%" C "/%" C " "
    "nxd=%" C "/%" C "/%" C " "
    "err=%" C "/%" C "/%" C " "
    "bad=%" C "/%" C "",
    (long)d,
    tot.nrep + tot.nnxd + tot.nerr + s->nbad,
    tot.irep + tot.inxd + tot.ierr,
    tot.orep + tot.onxd + tot.oerr,
    tot.arep,
    tot.nrep, tot.irep, tot.orep, tot.arep,
    tot.nnxd, tot.inxd, tot.onxd,
    tot.nerr, tot.ierr, tot.oerr,
    s->nbad, s->ibad);
  for(z = zone; z; z = z->z_next) {
    dns_dntop(z->z_dn, name, sizeof(name));
    dslog(LOG_INFO, 0,
      "stats for %ldsecs zone %.60s (num/in/out/ans): "
      "tot=%" C "/%" C "/%" C "/%" C " "
      "ok=%" C "/%" C "/%" C "/%" C " "
      "nxd=%" C "/%" C "/%" C " "
      "err=%" C "/%" C "/%" C "",
      (long)d, name,
      z->z_stats.nrep + z->z_stats.nnxd + z->z_stats.nerr,
      z->z_stats.irep + z->z_stats.inxd + z->z_stats.ierr,
      z->z_stats.orep + z->z_stats.onxd + z->z_stats.oerr,
      z->z_stats.arep,
      z->z_stats.nrep, z->z_stats.irep, z->z_stats.orep, z->z_stats.arep,
      z->z_stats.nnxd, z->z_stats.inxd, z->z_stats.onxd,
      z->z_stats.nerr, z->z_stats.ierr, z->z_stats.oerr);
  }
#undef C
  if (reset) {
    for(z = zone; z; z = z->z_next)
      memset(&z->z_stats, 0, sizeof(z->z_stats));
    memset(s, 0, sizeof(*s));
    s->stime = t;
  }
}
#else
# define logstats(s,z,r)
#endif

static FILE *reopenlog(FILE *flog, const char *logfile) {
  int fd;
  if (flog) fclose(flog);
  fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0644);
  if (fd >= 0 && (flog = fdopen(fd, "a")) != NULL)
    return flog;
  dslog(LOG_WARNING, 0, "error (re)opening logfile `%.50s': %s",
        logfile, strerror(errno));
  if (fd >= 0) close(fd);
  return NULL;
}

int main(int argc, char **argv) {
  int fd;
  struct zone *zonelist = NULL;
  struct sdnsstats stats;
  FILE *flog;
  int q, r;
#ifndef NOIPv6
  struct sockaddr_storage sa;
#else
  struct sockaddr_in sa;
#endif
  socklen_t salen;
  struct dnspacket pkt;
  int flushlog = 0;
  struct zone *zone;

  fd = init(argc, argv, &zonelist);
  setup_signals();
  if (logfile) {
    if (*logfile == '+') flushlog = 1, ++logfile;
    flog = reopenlog(NULL, logfile);
  }
  else
    flog = NULL;
  alarm(recheck);
#ifndef NOSTATS
  memset(&stats, 0, sizeof(stats));
  stats.stime = time(NULL);
#endif

  for(;;) {

    if (signalled) {
      sigset_t ssorig;
      sigprocmask(SIG_BLOCK, &ssblock, &ssorig);
      if (signalled & SIGNALLED_TERM) {
        dslog(LOG_INFO, 0, "terminating");
        logstats(&stats, zonelist, 0);
        logmemusage();
        return 0;
      }
      if (signalled & SIGNALLED_STATS) {
        logstats(&stats, zonelist, signalled & SIGNALLED_ZEROSTATS);
        logmemusage();
      }
      if ((signalled & SIGNALLED_RELOG) && logfile)
        flog = reopenlog(flog, logfile);
      if (signalled & SIGNALLED_RELOAD)
        do_reload(zonelist);
      signalled = 0;
      sigprocmask(SIG_SETMASK, &ssorig, NULL);
    }

    salen = sizeof(sa);
    q = recvfrom(fd, pkt.p_buf, sizeof(pkt.p_buf), 0,
                 (struct sockaddr *)&sa, &salen);
    if (q <= 0)			/* interrupted? */
      continue;

    zone = NULL;
    r = replypacket(&pkt, q, zonelist, &zone);
    if (!r) {
#ifndef NOSTATS
      stats.nbad += 1;
      stats.ibad += q;
#endif
      continue;
    }
    if (flog)
      logreply(&pkt, (struct sockaddr *)&sa, salen, flog, flushlog);
#ifndef NOSTATS
    if (!zone) { stats.nbad += 1; stats.ibad += 1; }
    else switch(pkt.p_buf[3]) {
    case DNS_R_NOERROR:
      zone->z_stats.nrep += 1; zone->z_stats.irep += q; zone->z_stats.orep += r;
      zone->z_stats.arep += pkt.p_buf[7]; /* arcount */
      break;
    case DNS_R_NXDOMAIN:
      zone->z_stats.nnxd += 1; zone->z_stats.inxd += q; zone->z_stats.onxd += r;
      break;
    default:
      zone->z_stats.nerr += 1; zone->z_stats.ierr += q; zone->z_stats.oerr += r;
      break;
    }
#endif

    /* finally, send a reply */
    while(sendto(fd, pkt.p_buf, r, 0, (struct sockaddr *)&sa, salen) < 0)
      if (errno != EINTR) break;

  }
}

unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np) {
  unsigned bits = ip4cidr(s, ap, np);
  if (bits) {
    ip4addr_t hmask = ~ip4mask(bits);
    if (*ap & hmask) {
      if (!accept_in_cidr) return 0;
      *ap &= hmask;
    }
  }
  return bits;
}

int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np) {
  unsigned bits = ip4range(s, a1p, a2p, np);
  if (!bits) return 0;
  if (*a1p & ~ip4mask(bits)) {
    if (accept_in_cidr) *a1p &= ip4mask(bits);
    else return 0;
  }
  return 1;
}

void oom() {
  if (initialized)
    dslog(LOG_ERR, 0, "out of memory loading dataset");
  else
    error(0, "out of memory");
}
