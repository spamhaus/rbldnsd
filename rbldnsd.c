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
#include "rbldnsd.h"

#ifdef NOPOLL
#include <sys/select.h>
#else
#include <sys/poll.h>
#endif
#ifndef NOMEMINFO
# include <malloc.h>
#endif
#ifndef NOTIMES
# include <sys/times.h>
#endif
#ifndef NOSTDINT_H
/* if system have stdint.h, assume it have inttypes.h too */
# include <inttypes.h>
#endif

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
const char *show_version = "rbldnsd " VERSION;
/* version to show in version.bind CH TXT reply */
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
unsigned char def_ttl[4] = "\0\0\010\064";	/* default record TTL 35m */
const char def_rr[5] = "\177\0\0\2\0";		/* default A RR */
struct dataset *ds_loading;

#define MAXSOCK	20	/* maximum # of supported sockets */
static int sock[MAXSOCK];
static int numsock;

/* a list of zonetypes. */
const struct dstype *ds_types[] = {
  &dataset_ip4set_type,
  &dataset_ip4trie_type,
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
static void logmemusage(void) {
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
#define sec(tm) tm/HZ, (tm*100/HZ)%100
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
"Usage is: %s options zonespec...\n"
"where options are:\n"
" -u user[:group] - run as this user:group (rbldns)\n"
" -r rootdir - chroot to this directory\n"
" -w workdir - working directory with zone files\n"
" -b address[/port] - bind to (listen on) this address (required)\n"
#ifndef NOIPv6
" -4 - use IPv4 socket type\n"
" -6 - use IPv6 socket type\n"
#endif
" -t ttl - TTL value set in answers (35m)\n"
" -v - hide version information in replies to version.bind CH TXT\n"
"  (second -v makes rbldnsd to refuse such requests completely)\n"
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

#ifdef NOIPv6
static void newsocket(struct sockaddr_in *sin) {
  int fd;
  const char *host = ip4atos(ntohl(sin->sin_addr.s_addr));
  if (numsock >= MAXSOCK)
    error(0, "too many listening sockets (%d max)", MAXSOCK);
  fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    error(errno, "unable to create socket");
  if (bind(fd, (struct sockaddr *)sin, sizeof(*sin)) < 0)
    error(errno, "unable to bind to %s/%d", host, ntohs(sin->sin_port));

  dslog(LOG_INFO, 0, "listening on %s/%d", host, ntohs(sin->sin_port));
  sock[numsock++] = fd;
}
#else
static int newsocket(struct addrinfo *ai) {
  int fd;
  char host[NI_MAXHOST], serv[NI_MAXSERV];

  if (numsock >= MAXSOCK)
    error(0, "too many listening sockets (%d max)", MAXSOCK);
  fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if (fd < 0) {
    if (errno == EAFNOSUPPORT) return 0;
    error(errno, "unable to create socket");
  }
  getnameinfo(ai->ai_addr, ai->ai_addrlen,
              host, sizeof(host), serv, sizeof(serv),
              NI_NUMERICHOST|NI_WITHSCOPEID|NI_NUMERICSERV);
  if (bind(fd, ai->ai_addr, ai->ai_addrlen) < 0)
        error(errno, "unable to bind to %s/%s", host, serv);

  dslog(LOG_INFO, 0, "listening on %s/%s", host, serv);
  sock[numsock++] = fd;
  return 1;
}
#endif

static void
initsockets(const char *bindaddr[MAXSOCK], int nba, int UNUSED family) {

  int i, x;
  char *host, *serv;
  const char *ba;

#ifdef NOIPv6

  struct sockaddr_in sin;
  ip4addr_t sinaddr;
  int port;
  struct servent *se;
  struct hostent *he;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;

  if (!(se = getservbyname("domain", "udp")))
    port = htons(DNS_PORT);
  else
    port = se->s_port;

#else

  struct addrinfo hints, *aires, *ai;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE;

#endif

  for (i = 0; i < nba; ++i) {
    ba = bindaddr[i];
    host = estrdup(ba);

    serv = strchr(host, '/');
    if (serv) {
      *serv++ = '\0';
      if (!*host)
        error(0, "missing host part in bind address `%.60s'", ba);
    }

#ifdef NOIPv6

    if (!serv || !*serv)
      sin.sin_port = port;
    else if ((x = satoi(serv)) > 0 && x <= 0xffff)
      sin.sin_port = htons(x);
    else if (!(se = getservbyname(serv, "udp")))
      error(0, "unknown service in `%.60s'", ba);
    else
      sin.sin_port = se->s_port;

    if (ip4addr(host, &sinaddr, NULL) > 0) {
      sin.sin_addr.s_addr = htonl(sinaddr);
      newsocket(&sin);
    }
    else if (!(he = gethostbyname(host))
             || he->h_addrtype != AF_INET
             || he->h_length != 4
             || !he->h_addr_list[0])
      error(0, "unknown host in `%.60s'", ba);
    else {
      for(x = 0; he->h_addr_list[x]; ++x) {
        memcpy(&sin.sin_addr, he->h_addr_list[x], 4);
        newsocket(&sin);
      }
    }

#else

    if (!serv || !*serv)
      serv = "domain";

    x = getaddrinfo(host, serv, &hints, &aires);
    if (x != 0)
      error(0, "%.60s: %s", ba, gai_strerror(x));
    for(ai = aires, x = 0; ai; ai = ai->ai_next)
      if (newsocket(ai))
        ++x;
    if (!x)
      error(0, "%.60s: no available protocols", ba);
    freeaddrinfo(aires);

#endif

    free(host);
  }
  endservent();
  endhostent();

  for (i = 0; i < numsock; ++i) {
    x = 65536;
    do
      if (setsockopt(sock[i], SOL_SOCKET, SO_RCVBUF, &x, sizeof x) == 0)
        break;
    while ((x -= (x >> 5)) >= 1024);
  }
}

static struct zone *init(int argc, char **argv) {
  int c;
  char *p;
  const char *user = NULL;
  const char *rootdir = NULL, *workdir = NULL, *pidfile = NULL;
  const char *bindaddr[MAXSOCK];
  int nba = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  int nodaemon = 0, quickstart = 0, dump = 0, nover = 0;
  int family = AF_UNSPEC;
  struct zone *zonelist = NULL;

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  if (argc <= 1) usage(1);

  while((c = getopt(argc, argv, "u:r:b:w:t:c:p:nel:qsh46dv")) != EOF)
    switch(c) {
    case 'u': user = optarg; break;
    case 'r': rootdir = optarg; break;
    case 'b':
      if (nba >= MAXSOCK)
        error(0, "too many addresses to listen on (%d max)", MAXSOCK);
      bindaddr[nba++] = optarg;
      break;
#ifndef NOIPv6
    case '4': family = AF_INET; break;
    case '6': family = AF_INET6; break;
#else
    case '4': break;
    case '6': error(0, "IPv6 support isn't compiled in");
#endif
    case 'w': workdir = optarg; break;
    case 'p': pidfile = optarg; break;
    case 't':
      if (!(p = parse_time_nb(optarg, def_ttl)) || *p)
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
    case 'v': show_version = nover++ ? NULL : "rbldnsd"; break;
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
      zonelist = addzone(zonelist, argv[c]);
    init_zones_caches(zonelist);
    if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
      error(errno, "unable to chroot to %.50s", rootdir);
    if (workdir && chdir(workdir) < 0)
      error(errno, "unable to chdir to %.50s", workdir);
    if (!do_reload(zonelist))
      error(0, "zone loading errors, aborting");
    now = time(NULL);
    printf("; zone dump made %s", ctime(&now));
    printf("; rbldnsd version %s\n", version);
    for (z = zonelist; z; z = z->z_next)
      dumpzone(z, stdout);
    fflush(stdout);
    exit(ferror(stdout) ? 1 : 0);
  }

  if (!nba)
    error(0, "no address to listen on (-b option) specified");

  tzset();
  if (nodaemon)
    logto = LOGTO_STDOUT|LOGTO_STDERR;
  else {
    /* fork early so that logging will be from right pid */
    int pfd[2];
    if (pipe(pfd) < 0) error(errno, "pipe() failed");
    c = fork();
    if (c < 0) error(errno, "fork() failed");
    if (c > 0) {
      close(pfd[1]);
      if (read(pfd[0], &c, 1) < 1) exit(1);
      else exit(0);
    }
    dup2(pfd[1], 500);
    close(pfd[0]); close(pfd[1]);
    openlog(progname, LOG_PID|LOG_NDELAY, LOG_DAEMON);
    logto = LOGTO_STDERR|LOGTO_SYSLOG;
    if (!quickstart) logto |= LOGTO_STDOUT;
  }

  initsockets(bindaddr, nba, family);

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

  if (pidfile) {
    int fdpid;
    char buf[40];
    c = sprintf(buf, "%ld\n", (long)getpid());
    fdpid = open(pidfile, O_CREAT|O_WRONLY|O_TRUNC, 0644);
    if (fdpid < 0 || write(fdpid, buf, c) < c)
      error(errno, "unable to write pidfile");
    close(fdpid);
  }

  if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
    error(errno, "unable to chroot to %.50s", rootdir);
  if (workdir && chdir(workdir) < 0)
    error(errno, "unable to chdir to %.50s", workdir);

  if (user)
    if (setgroups(1, &gid) < 0 || setgid(gid) < 0 || setuid(uid) < 0)
      error(errno, "unable to setuid(%d:%d)", uid, gid);

  for(c = 0; c < argc; ++c)
    zonelist = addzone(zonelist, argv[c]);
  init_zones_caches(zonelist);

  if (quickstart)
    signalled = SIGNALLED_RELOAD;	/* zones will be loaded after fork */
  else if (!do_reload(zonelist))
    error(0, "zone loading errors, aborting");

  dslog(LOG_INFO, 0, "rbldnsd version %s started (%d socket(s))",
        version, numsock);
  initialized = 1;

  if (!nodaemon) {
    write(500, "", 1);
    close(500);
    close(0); close(1); close(2);
    setsid();
    logto = LOGTO_SYSLOG;
  }

  return zonelist;
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

static void setup_signals(void) {
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

static struct dnsstats gstats;
static time_t stats_time;

static void logstats(struct zone *zonelist, int reset) {
  time_t t = time(NULL);
  time_t d = t - stats_time;
  struct dnsstats tot = gstats;
  char name[DNS_MAXDOMAIN+1];
  struct zone *z;
  for (z = zonelist; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(nnxd); add(inxd); add(onxd);
    add(nrep); add(irep); add(orep); add(arep);
    add(nerr); add(ierr); add(oerr);
#undef add
  }
#define C PRI_DNSCNT
  dslog(LOG_INFO, 0,
    "stats for %ldsec (num/in/out/ans): "
    "tot=%" C "/%" C "/%" C "/%" C " "
    "ok=%" C "/%" C "/%" C "/%" C " "
    "nxd=%" C "/%" C "/%" C " "
    "err=%" C "/%" C "/%" C,
    (long)d,
    tot.nrep + tot.nnxd + tot.nerr,
    tot.irep + tot.inxd + tot.ierr,
    tot.orep + tot.onxd + tot.oerr,
    tot.arep,
    tot.nrep, tot.irep, tot.orep, tot.arep,
    tot.nnxd, tot.inxd, tot.onxd,
    tot.nerr, tot.ierr, tot.oerr);
  for(z = zonelist; z; z = z->z_next) {
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
    for(z = zonelist; z; z = z->z_next)
      memset(&z->z_stats, 0, sizeof(z->z_stats));
    memset(&gstats, 0, sizeof(gstats));
    stats_time = t;
  }
}
#else
# define logstats(z,r)
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

static FILE *flog;
static int flushlog;
static struct zone *zonelist;

static void do_signalled() {
  sigset_t ssorig;
  sigprocmask(SIG_BLOCK, &ssblock, &ssorig);
  if (signalled & SIGNALLED_TERM) {
    dslog(LOG_INFO, 0, "terminating");
    logstats(zonelist, 0);
    logmemusage();
    exit(0);
  }
  if (signalled & SIGNALLED_STATS) {
    logstats(zonelist, signalled & SIGNALLED_ZEROSTATS);
    logmemusage();
  }
  if ((signalled & SIGNALLED_RELOG) && logfile)
    flog = reopenlog(flog, logfile);
  if (signalled & SIGNALLED_RELOAD)
    do_reload(zonelist);
  signalled = 0;
  sigprocmask(SIG_SETMASK, &ssorig, NULL);
}

static void request(int fd) {
  int q, r;
#ifndef NOIPv6
  struct sockaddr_storage sa;
#else
  struct sockaddr_in sa;
#endif
  socklen_t salen = sizeof(sa);
  struct dnspacket pkt;
  struct zone *zone;
#ifndef NOSTATS
  struct dnsstats *sp;
#endif

  salen = sizeof(sa);
  q = recvfrom(fd, pkt.p_buf, sizeof(pkt.p_buf), 0,
               (struct sockaddr *)&sa, &salen);
  if (q <= 0)			/* interrupted? */
    return;

  zone = NULL;
  r = replypacket(&pkt, q, zonelist, &zone);
  if (!r) {
#ifndef NOSTATS
    gstats.nerr += 1;
    gstats.ierr += q;
#endif
    return;
  }
  if (flog)
    logreply(&pkt, (struct sockaddr *)&sa, salen, flog, flushlog);
#ifndef NOSTATS
  sp = zone ? &zone->z_stats : &gstats;
  switch(pkt.p_buf[3]) {
  case DNS_R_NOERROR:
    sp->nrep += 1; sp->irep += q; sp->orep += r;
    sp->arep += pkt.p_buf[7]; /* arcount */
    break;
  case DNS_R_NXDOMAIN:
    sp->nnxd += 1; sp->inxd += q; sp->onxd += r;
    break;
  default:
    sp->nerr += 1; sp->ierr += q; sp->oerr += r;
    break;
  }
#endif

  /* finally, send a reply */
  while(sendto(fd, pkt.p_buf, r, 0, (struct sockaddr *)&sa, salen) < 0)
    if (errno != EINTR) break;

}

int main(int argc, char **argv) {
  zonelist = init(argc, argv);
  setup_signals();
  if (logfile) {
    if (*logfile == '+') flushlog = 1, ++logfile;
    flog = reopenlog(NULL, logfile);
  }
  else
    flog = NULL;
  alarm(recheck);
#ifndef NOSTATS
  stats_time = time(NULL);
#endif

  if (numsock == 1) {
    /* optimized case for only one socket */
    int fd = sock[0];
    for(;;) {
      if (signalled) do_signalled();
      request(fd);
    }
  }
  else {
    /* several sockets, do select/poll loop */
#ifdef NOPOLL
    fd_set rfds;
    int maxfd = 0;
    int *fdi, *fde = sock + numsock;
    FD_ZERO(&rfds);
    for (fdi = sock; fdi < fde; ++fdi) {
      FD_SET(*fdi, &rfds);
      if (*fdi > maxfd) maxfd = *fdi;
    }
    ++maxfd;
    for(;;) {
      fd_set rfd = rfds;
      if (signalled) do_signalled();
      if (select(maxfd, &rfd, NULL, NULL, NULL) <= 0)
        continue;
      for(fdi = sock; fdi < fde; ++fdi) {
        if (FD_ISSET(*fdi, &rfd))
          request(*fdi);
      }
    }
#else /* !NOPOLL */
    struct pollfd pfda[MAXSOCK];
    struct pollfd *pfdi, *pfde = pfda + numsock;
    int r;
    for(r = 0; r < numsock; ++r) {
      pfda[r].fd = sock[r];
      pfda[r].events = POLLIN;
    }
    for(;;) {
      if (signalled) do_signalled();
      r = poll(pfda, numsock, -1);
      if (r <= 0) continue;
      for(pfdi = pfda; pfdi < pfde; ++pfdi) {
        if (!(pfdi->revents & POLLIN)) continue;
        request(pfdi->fd);
        if (!--r) break;
      }
    }
#endif /* NOPOLL */
  }
}

unsigned ip4parse_cidr(const char *s, ip4addr_t *ap, char **np) {
  int bits = ip4cidr(s, ap, np);
  if (bits <= 0)
    return 0;
  if (*ap & ~ip4mask(bits)) {
    if (!accept_in_cidr) return 0;
    *ap &= ip4mask(bits);
  }
  return (unsigned)bits;
}

int ip4parse_range(const char *s, ip4addr_t *a1p, ip4addr_t *a2p, char **np) {
  int bits = ip4range(s, a1p, a2p, np);
  if (bits <= 0) return 0;
  if (*a1p & ~ip4mask(bits)) {
    if (accept_in_cidr) *a1p &= ip4mask(bits);
    else return 0;
  }
  return 1;
}

void oom(void) {
  if (initialized)
    dslog(LOG_ERR, 0, "out of memory loading dataset");
  else
    error(0, "out of memory");
}
