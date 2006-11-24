/* $Id$
 * rbldnsd: main program
 */

#define _LARGEFILE64_SOURCE /* to define O_LARGEFILE if supported */

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
#include <sys/time.h>	/* some systems can't include time.h and sys/time.h */
#include <fcntl.h>
#include <sys/wait.h>
#include "rbldnsd.h"

#ifndef NO_SELECT_H
# include <sys/select.h>
#endif
#ifndef NO_POLL
# include <sys/poll.h>
#endif
#ifndef NO_MEMINFO
# include <malloc.h>
#endif
#ifndef NO_TIMES
# include <sys/times.h>
#endif
#ifndef NO_STDINT_H
/* if system have stdint.h, assume it have inttypes.h too */
# include <inttypes.h>
#endif
#ifndef NO_STATS
# ifndef NO_IOVEC
#  include <sys/uio.h>
#  define STATS_IPC_IOVEC 1
# endif
#endif
#ifndef NO_DSO
# include <dlfcn.h>
#endif

#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif
#ifndef NI_MAXSERV
# define NI_MAXSERV 32
#endif

#ifndef O_LARGEFILE
# define O_LARGEFILE 0
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
static int initialized;		/* 1 when initialized */
static char *logfile;		/* log file name */
#ifndef NO_STATS
static char *statsfile;		/* statistics file */
static int stats_relative;	/* dump relative, not absolute, stats */
#endif
int accept_in_cidr;		/* accept 127.0.0.1/8-"style" CIDRs */
int nouncompress;		/* disable on-the-fly decompression */
unsigned def_ttl = 35*60;	/* default record TTL 35m */
unsigned min_ttl, max_ttl;	/* TTL constraints */
const char def_rr[5] = "\177\0\0\2\0";		/* default A RR */

#define MAXSOCK	20	/* maximum # of supported sockets */
static int sock[MAXSOCK];	/* array of active sockets */
static int numsock;		/* number of active sockets in sock[] */
static FILE *flog;		/* log file */
static int flushlog;		/* flush log after each line */
static struct zone *zonelist;	/* list of zones we're authoritative for */
static int numzones;		/* number of zones in zonelist */
int lazy;			/* don't return AUTH section by default */
static int fork_on_reload;
  /* >0 - perform fork on reloads, <0 - this is a child of reloading parent */
#if STATS_IPC_IOVEC
static struct iovec *stats_iov;
#endif
#ifndef NO_DSO
int (*hook_reload_check)(), (*hook_reload)();
int (*hook_query_access)(), (*hook_query_result)();
#endif

/* a list of zonetypes. */
const struct dstype *ds_types[] = {
  dstype(ip4set),
  dstype(ip4tset),
  dstype(ip4trie),
  dstype(dnset),
#ifdef DNHASH
  dstype(dnhasn),
#endif
  dstype(combined),
  dstype(generic),
  dstype(acl),
  NULL
};

static int do_reload(int do_fork);

static int satoi(const char *s) {
  int n = 0;
  if (*s < '0' || *s > '9') return -1;
  do n = n * 10 + (*s++ - '0');
  while (*s >= '0' && *s <= '9');
  return *s ? -1 : n;
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
#ifndef NO_IPv6
" -4 - use IPv4 socket type\n"
" -6 - use IPv6 socket type\n"
#endif
" -t ttl - default TTL value to set in answers (35m)\n"
" -v - hide version information in replies to version.bind CH TXT\n"
"  (second -v makes rbldnsd to refuse such requests completely)\n"
" -e - enable CIDR ranges where prefix is not on the range boundary\n"
"  (by default ranges such 127.0.0.1/8 will be rejected)\n"
" -c check - time interval to check for data file updates (1m)\n"
" -p pidfile - write pid to specified file\n"
" -n - do not become a daemon\n"
" -f - fork a child process while reloading zones, to process requests\n"
"  during reload (may double memory requiriments)\n"
" -q - quickstart, load zones after backgrounding\n"
" -l [+]logfile - log queries and answers to this file (+ for unbuffered)\n"
#ifndef NO_STATS
" -s [+]statsfile - write a line with short statistics summary into this\n"
"  file every `check' (-c) secounds, for rrdtool-like applications\n"
"  (+ to log relative, not absolute, statistics counters)\n"
#endif
" -a - omit AUTH section from regular replies, do not return list of\n"
"  nameservers, but only return NS info when explicitly asked.\n"
"  This is an equivalent of bind9 \"minimal-answers\" setting.\n"
"  In future versions this mode will be the default.\n"
" -A - put AUTH section in every reply.\n"
#ifndef NO_ZLIB
" -C - disable on-the-fly decompression of dataset files\n"
#endif
#ifndef NO_DZO
" -x extension - load given extension module (.so file)\n"
" -X extarg - pass extarg to extension init routine\n"
#endif
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
#define SIGNALLED_LSTATS	0x04
#define SIGNALLED_SSTATS	0x08
#define SIGNALLED_ZSTATS	0x10
#define SIGNALLED_TERM		0x20

#ifdef NO_IPv6
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
              NI_NUMERICHOST|NI_NUMERICSERV);
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

#ifdef NO_IPv6

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

#ifdef NO_IPv6

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
      if (setsockopt(sock[i], SOL_SOCKET, SO_RCVBUF, (void*)&x, sizeof x) == 0)
        break;
    while ((x -= (x >> 5)) >= 1024);
  }
}

static void init(int argc, char **argv) {
  int c;
  char *p;
  const char *user = NULL;
  const char *rootdir = NULL, *workdir = NULL, *pidfile = NULL;
  const char *bindaddr[MAXSOCK];
  int nba = 0;
  uid_t uid = 0;
  gid_t gid = 0;
  int nodaemon = 0, quickstart = 0, dump = 0, nover = 0, forkon = 0;
  int family = AF_UNSPEC;
  int cfd = -1;
  const struct zone *z;
#ifndef NO_DSO
  char *ext = NULL, *extarg = NULL;
  int (*extinit)(const char *arg, struct zone *zonelist) = NULL;
#endif

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  if (argc <= 1) usage(1);

  while((c = getopt(argc, argv, "u:r:b:w:t:c:p:nel:qs:h46dvaAfCx:X:")) != EOF)
    switch(c) {
    case 'u': user = optarg; break;
    case 'r': rootdir = optarg; break;
    case 'b':
      if (nba >= MAXSOCK)
        error(0, "too many addresses to listen on (%d max)", MAXSOCK);
      bindaddr[nba++] = optarg;
      break;
#ifndef NO_IPv6
    case '4': family = AF_INET; break;
    case '6': family = AF_INET6; break;
#else
    case '4': break;
    case '6': error(0, "IPv6 support isn't compiled in");
#endif
    case 'w': workdir = optarg; break;
    case 'p': pidfile = optarg; break;
    case 't':
      p = optarg;
      if (*p == ':') ++p;
      else {
        if (!(p = parse_time(p, &def_ttl)) || !def_ttl ||
            (*p && *p++ != ':'))
          error(0, "invalid ttl (-t) value `%.50s'", optarg);
      }
      if (*p == ':') ++p;
      else if (*p) {
        if (!(p = parse_time(p, &min_ttl)) || (*p && *p++ != ':'))
          error(0, "invalid minttl (-t) value `%.50s'", optarg);
      }
      if (*p == ':') ++p;
      else if (*p) {
        if (!(p = parse_time(p, &max_ttl)) || (*p && *p++ != ':'))
          error(0, "invalid maxttl (-t) value `%.50s'", optarg);
      }
      if (*p)
        error(0, "invalid value for -t (ttl) option: `%.50s'", optarg);
      if ((min_ttl && max_ttl && min_ttl > max_ttl) ||
          (min_ttl && def_ttl < min_ttl) ||
          (max_ttl && def_ttl > max_ttl))
        error(0, "inconsistent def:min:max ttl: %u:%u:%u",
              def_ttl, min_ttl, max_ttl);
      break;
    case 'c':
      if (!(p = parse_time(optarg, &recheck)) || *p)
        error(0, "invalid check interval (-c) value `%.50s'", optarg);
      break;
    case 'n': nodaemon = 1; break;
    case 'e': accept_in_cidr = 1; break;
    case 'l':
      logfile = optarg;
      if (*logfile != '+') flushlog = 0;
      else ++logfile, flushlog = 1;
      if (!*logfile) logfile = NULL, flushlog = 0;
      else if (logfile[0] == '-' && logfile[1] == '\0')
        logfile = NULL, flog = stdout;
      break;
break;
    case 's':
#ifdef NO_STATS
      fprintf(stderr,
        "%s: warning: no statistics counters support is compiled in\n",
        progname);
#else
      statsfile = optarg;
      if (*statsfile != '+') stats_relative = 0;
      else ++statsfile, stats_relative = 1;
      if (!*statsfile) statsfile = NULL;
#endif
      break;
    case 'q': quickstart = 1; break;
    case 'd':
#ifdef NO_MASTER_DUMP
      error(0, "master-format dump option (-d) isn't compiled in");
#endif
      dump = 1;
      break;
    case 'v': show_version = nover++ ? NULL : "rbldnsd"; break;
    case 'a': lazy = 1; break;
    case 'A': lazy = 0; break;
    case 'f': forkon = 1; break;
    case 'C': nouncompress = 1; break;
#ifndef NO_DSO
    case 'x': ext = optarg; break;
    case 'X': extarg = optarg; break;
#else
    case 'x':
    case 'X':
      error(0, "extension support is not compiled in");
#endif
    case 'h': usage(0);
    default: error(0, "type `%.50s -h' for help", progname);
    }

  if (!(argc -= optind))
    error(0, "no zone(s) to service specified (-h for help)");
  argv += optind;

#ifndef NO_MASTER_DUMP
  if (dump) {
    time_t now;
    logto = LOGTO_STDERR;
    for(c = 0; c < argc; ++c)
      zonelist = addzone(zonelist, argv[c]);
    init_zones_caches(zonelist);
    if (rootdir && (chdir(rootdir) < 0 || chroot(rootdir) < 0))
      error(errno, "unable to chroot to %.50s", rootdir);
    if (workdir && chdir(workdir) < 0)
      error(errno, "unable to chdir to %.50s", workdir);
    if (!do_reload(0))
      error(0, "zone loading errors, aborting");
    now = time(NULL);
    printf("; zone dump made %s", ctime(&now));
    printf("; rbldnsd version %s\n", version);
    for (z = zonelist; z; z = z->z_next)
      dumpzone(z, stdout);
    fflush(stdout);
    exit(ferror(stdout) ? 1 : 0);
  }
#endif

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
    cfd = pfd[1];
    close(pfd[0]);
    openlog(progname, LOG_PID|LOG_NDELAY, LOG_DAEMON);
    logto = LOGTO_STDERR|LOGTO_SYSLOG;
    if (!quickstart && !flog) logto |= LOGTO_STDOUT;
  }

  initsockets(bindaddr, nba, family);

#ifndef NO_DSO
  if (ext) {
    void *handle = dlopen(ext, RTLD_NOW);
    if (!handle)
      error(0, "unable to load extension `%s': %s", ext, dlerror());
    extinit = dlsym(handle, "rbldnsd_extension_init");
    if (!extinit)
      error(0, "unable to find extension init routine in `%s'", ext);
  }
#endif

  if (!user && !(uid = getuid()))
    user = "rbldns";

  if (!user)
    p = NULL;
  else {
    if ((p = strchr(user, ':')) != NULL)
      *p++ = '\0';
    if ((c = satoi(user)) >= 0)
      uid = c, gid = c;
    else {
      struct passwd *pw = getpwnam(user);
      if (!pw)
        error(0, "unknown user `%s'", user);
      uid = pw->pw_uid;
      gid = pw->pw_gid;
      endpwent();
    }
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
      error(errno, "unable to setuid(%d:%d)", (int)uid, (int)gid);

  for(c = 0; c < argc; ++c)
    zonelist = addzone(zonelist, argv[c]);
  init_zones_caches(zonelist);

#ifndef NO_DSO
  if (extinit && extinit(extarg, zonelist) != 0)
    error(0, "unable to iniitialize extension `%s'", ext);
#endif

  if (!quickstart && !do_reload(0))
    error(0, "zone loading errors, aborting");

  /* count number of zones */
  for(c = 0, z = zonelist; z; z = z->z_next)
    ++c;
  numzones = c;

#if STATS_IPC_IOVEC
  stats_iov = (struct iovec *)emalloc(numzones * sizeof(struct iovec));
  for(c = 0, z = zonelist; z; z = z->z_next, ++c) {
    stats_iov[c].iov_base = (char*)&z->z_stats;
    stats_iov[c].iov_len = sizeof(z->z_stats);
  }
#endif
  dslog(LOG_INFO, 0, "rbldnsd version %s started (%d socket(s), %d zone(s))",
        version, numsock, numzones);
  initialized = 1;

  if (cfd >= 0) {
    write(cfd, "", 1);
    close(cfd);
    close(0); close(2);
    if (!flog) close(1);
    setsid();
    logto = LOGTO_SYSLOG;
  }

  if (quickstart)
    do_reload(0);

  /* only set "main" fork_on_reload after first reload */
  fork_on_reload = forkon;
}

static void sighandler(int sig) {
  switch(sig) {
  case SIGHUP:
    signalled |= SIGNALLED_RELOG|SIGNALLED_RELOAD;
    break;
  case SIGALRM:
#ifndef HAVE_SETITIMER
    alarm(recheck);
#endif
    signalled |= SIGNALLED_RELOAD|SIGNALLED_SSTATS;
    break;
#ifndef NO_STATS
  case SIGUSR1:
    signalled |= SIGNALLED_LSTATS|SIGNALLED_SSTATS;
    break;
  case SIGUSR2:
    signalled |= SIGNALLED_LSTATS|SIGNALLED_SSTATS|SIGNALLED_ZSTATS;
    break;
#endif
  case SIGTERM:
  case SIGINT:
    signalled |= SIGNALLED_TERM;
    break;
  }
}

static sigset_t ssblock; /* signals to block during zone reload */
static sigset_t ssempty; /* empty set */

static void setup_signals(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sighandler;
  sigemptyset(&ssblock);
  sigemptyset(&ssempty);
  sigaction(SIGHUP, &sa, NULL);
  sigaddset(&ssblock, SIGHUP);
  sigaction(SIGALRM, &sa, NULL);
  sigaddset(&ssblock, SIGALRM);
#ifndef NO_STATS
  sigaction(SIGUSR1, &sa, NULL);
  sigaddset(&ssblock, SIGUSR1);
  sigaction(SIGUSR2, &sa, NULL);
  sigaddset(&ssblock, SIGUSR2);
#endif
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  signal(SIGPIPE, SIG_IGN);	/* in case logfile is FIFO */
}

#ifndef NO_STATS

struct dnsstats gstats;
static struct dnsstats gptot;
static time_t stats_time;

static void dumpstats(void) {
  struct dnsstats tot;
  char name[DNS_MAXDOMAIN+1];
  FILE *f;
  struct zone *z;

  f = fopen(statsfile, "a");

  if (f)
    fprintf(f, "%ld", (long)time(NULL));

#define C ":%" PRI_DNSCNT
  tot = gstats;
  for(z = zonelist; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(b_in); add(b_out);
    add(q_ok); add(q_nxd); add(q_err);
#undef add
    if (f) {
      dns_dntop(z->z_dn, name, sizeof(name));
#define delta(x) z->z_stats.x - z->z_pstats.x
      fprintf(f, " %s" C C C C C,
        name,
        delta(q_ok) + delta(q_nxd) + delta(q_err),
        delta(q_ok), delta(q_nxd),
        delta(b_in), delta(b_out));
#undef delta
    }
    if (stats_relative)
      z->z_pstats = z->z_stats;
  }
  if (f) {
#define delta(x) tot.x - gptot.x
    fprintf(f, " *" C C C C C "\n",
      delta(q_ok) + delta(q_nxd) + delta(q_err),
      delta(q_ok), delta(q_nxd),
      delta(b_in), delta(b_out));
#undef delta
    fclose(f);
  }
  if (stats_relative)
    gptot = tot;
#undef C
}

static void dumpstats_z(void) {
  FILE *f = fopen(statsfile, "a");
  if (f) {
    fprintf(f, "%ld\n", (long)time(NULL));
    fclose(f);
  }
}

static void logstats(int reset) {
  time_t t = time(NULL);
  time_t d = t - stats_time;
  struct dnsstats tot = gstats;
  char name[DNS_MAXDOMAIN+1];
  struct zone *z;

#define C(x) " " #x "=%" PRI_DNSCNT
  for(z = zonelist; z; z = z->z_next) {
#define add(x) tot.x += z->z_stats.x
    add(b_in); add(b_out);
    add(q_ok); add(q_nxd); add(q_err);
#undef add
    dns_dntop(z->z_dn, name, sizeof(name));
    dslog(LOG_INFO, 0,
      "stats for %ldsecs zone %.60s:" C(tot) C(ok) C(nxd) C(err) C(in) C(out),
      (long)d, name,
      z->z_stats.q_ok + z->z_stats.q_nxd + z->z_stats.q_err,
      z->z_stats.q_ok, z->z_stats.q_nxd, z->z_stats.q_err,
      z->z_stats.b_in, z->z_stats.b_out);
  }
  dslog(LOG_INFO, 0,
    "stats for %ldsec:" C(tot) C(ok) C(nxd) C(err) C(in) C(out),
    (long)d,
    tot.q_ok + tot.q_nxd + tot.q_err,
    tot.q_ok, tot.q_nxd, tot.q_err,
    tot.b_in, tot.b_out);
#undef C
  if (reset) {
    for(z = zonelist; z; z = z->z_next) {
      memset(&z->z_stats, 0, sizeof(z->z_stats));
      memset(&z->z_pstats, 0, sizeof(z->z_pstats));
    }
    memset(&gstats, 0, sizeof(gstats));
    memset(&gptot, 0, sizeof(gptot));
    stats_time = t;
  }
}

#if STATS_IPC_IOVEC
# define ipc_read_stats(fd)  readv(fd, stats_iov, numzones)
# define ipc_write_stats(fd) writev(fd, stats_iov, numzones)
#else
static void ipc_read_stats(int fd) {
  struct zone *z;
  for(z = zonelist; z; z = z->z_next)
    if (read(fd, &z->z_stats, sizeof(z->z_stats)) <= 0)
      break;
}
static void ipc_write_stats(int fd) {
  const struct zone *z;
  for(z = zonelist; z; z = z->z_next)
    if (write(fd, &z->z_stats, sizeof(z->z_stats)) <= 0)
      break;
}
#endif

#else
# define ipc_read_stats(fd)
# define ipc_write_stats(fd)
#endif

static void reopenlog(void) {
  if (logfile) {
    int fd;
    if (flog) fclose(flog);
    fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK|O_LARGEFILE, 0644);
    if (fd < 0 || (flog = fdopen(fd, "a")) == NULL) {
      dslog(LOG_WARNING, 0, "error (re)opening logfile `%.50s': %s",
            logfile, strerror(errno));
      if (fd >= 0) close(fd);
      flog = NULL;
    }
  }
  else if (flog && !flushlog) { /* log to stdout */
    clearerr(flog);
    fflush(flog);
  }
}

static void check_expires(void) {
  struct zone *zone;
  time_t now = time(NULL);
  for (zone = zonelist; zone; zone = zone->z_next) {
    if (!zone->z_stamp)
      continue;
    if (zone->z_expires && zone->z_expires < now) {
      zlog(LOG_WARNING, zone, "zone data expired, zone will not be serviced");
      zone->z_stamp = 0;
    }
  }
}

static int do_reload(int do_fork) {
  int r;
  char ibuf[150];
  int ip;
  struct dataset *ds;
  struct zone *zone;
  pid_t cpid = 0;	/* child pid; =0 to make gcc happy */
  int cfd = 0;		/* child stats fd; =0 to make gcc happy */
#ifndef NO_TIMES
  struct tms tms;
  clock_t utm, etm;
#ifndef HZ
  static clock_t HZ;
#endif
#endif /* NO_TIMES */

  ds = nextdataset2reload(NULL);
  if (!ds && call_hook(reload_check, (zonelist)) == 0) {
    check_expires();
    return 1;	/* nothing to reload */
  }

  if (do_fork) {
    int pfd[2];
    if (flog && !flushlog)
      fflush(flog);
    /* forking reload. if anything fails, just do a non-forking one */
    if (pipe(pfd) < 0)
      do_fork = 0;
    else if ((cpid = fork()) < 0) {	/* fork failed, close the pipe */
      close(pfd[0]);
      close(pfd[1]);
      do_fork = 0;
    }
    else if (!cpid) {	/* child, continue answering queries */
      signal(SIGALRM, SIG_IGN);
      signal(SIGHUP, SIG_IGN);
#ifndef NO_STATS
      signal(SIGUSR1, SIG_IGN);
      signal(SIGUSR2, SIG_IGN);
#endif
      close(pfd[0]);
      /* set up the fd#1 to write stats later on SIGTERM */
      if (pfd[1] != 1) {
        dup2(pfd[1], 1);
        close(pfd[1]);
      }
      fork_on_reload = -1;
      return 1;
    }
    else {
      close(pfd[1]);
      cfd = pfd[0];
    }
  }

#ifndef NO_TIMES
#ifndef HZ
  if (!HZ)
    HZ = sysconf(_SC_CLK_TCK);
#endif
  etm = times(&tms);
  utm = tms.tms_utime;
#endif /* NO_TIMES */

  r = 1;
  while(ds) {
    if (!loaddataset(ds))
      r = 0;
    ds = nextdataset2reload(ds);
  }

  for (zone = zonelist; zone; zone = zone->z_next) {
    time_t stamp = 0;
    time_t expires = 0;
    const struct dssoa *dssoa = NULL;
    const struct dsns *dsns = NULL;
    unsigned nsttl = 0;
    struct dslist *dsl;

    for(dsl = zone->z_dsl; dsl; dsl = dsl->dsl_next) {
      const struct dataset *ds = dsl->dsl_ds;
      if (!ds->ds_stamp) {
        stamp = 0;
        break;
      }
      if (stamp < ds->ds_stamp)
        stamp = ds->ds_stamp;
      if (ds->ds_expires && (!expires || expires > ds->ds_expires))
        expires = ds->ds_expires;
      if (!dssoa)
        dssoa = ds->ds_dssoa;
      if (!dsns)
        dsns = ds->ds_dsns, nsttl = ds->ds_nsttl;
    }

    zone->z_expires = expires;
    zone->z_stamp = stamp;
    if (!stamp) {
      zlog(LOG_WARNING, zone,
           "not all datasets are loaded, zone will not be serviced");
      r = 0;
    }
    else if (!update_zone_soa(zone, dssoa) ||
             !update_zone_ns(zone, dsns, nsttl, zonelist))
      zlog(LOG_WARNING, zone,
           "NS or SOA RRs are too long, will be ignored");
  }

  if (call_hook(reload, (zonelist)) != 0)
    r = 0;

  ip = ssprintf(ibuf, sizeof(ibuf), "zones reloaded");
#ifndef NO_TIMES
  etm = times(&tms) - etm;
  utm = tms.tms_utime - utm;
# define sec(tm) (unsigned long)(tm/HZ), (unsigned long)((tm*100/HZ)%100)
  ip += ssprintf(ibuf + ip, sizeof(ibuf) - ip,
        ", time %lu.%lue/%lu.%luu sec", sec(etm), sec(utm));
# undef sec
#endif /* NO_TIMES */
#ifndef NO_MEMINFO
  {
    struct mallinfo mi = mallinfo();
# define kb(x) ((mi.x + 512)>>10)
    ip += ssprintf(ibuf + ip, sizeof(ibuf) - ip,
          ", mem arena=%d free=%d mmap=%d Kb",
          kb(arena), kb(fordblks), kb(hblkhd));
# undef kb
  }
#endif /* NO_MEMINFO */
  dslog(LOG_INFO, 0, ibuf);

  check_expires();

  /* ok, (something) loaded. */

  if (do_fork) {
    /* here we should notify query-answering child (send SIGTERM to it),
     * and wait for it to complete.
     * Unfortunately at least on linux, the SIGTERM sometimes gets ignored
     * by the child process, so we're trying several times here, in a loop.
     */
    int s, n;
    fd_set fds;
    struct timeval tv;

    for(n = 1; ++n;) {
      if (kill(cpid, SIGTERM) != 0)
        dslog(LOG_WARNING, 0, "kill(qchild): %s", strerror(errno));
      FD_ZERO(&fds);
      FD_SET(cfd, &fds);
      tv.tv_sec = 0;
      tv.tv_usec = 500000;
      s = select(cfd+1, &fds, NULL, NULL, &tv);
      if (s > 0) break;
      dslog(LOG_WARNING, 0, "waiting for qchild process: %s, retrying",
            s ? strerror(errno) : "timeout");
    }
    ipc_read_stats(cfd);
    close(cfd);
    wait(&s);
  }

  return r;
}

static void do_signalled(void) {
  sigprocmask(SIG_SETMASK, &ssblock, NULL);
  if (signalled & SIGNALLED_TERM) {
    if (fork_on_reload < 0) { /* this is a temp child; dump stats and exit */
      ipc_write_stats(1);
      if (flog && !flushlog)
        fflush(flog);
      _exit(0);
    }
    dslog(LOG_INFO, 0, "terminating");
#ifndef NO_STATS
    if (statsfile)
      dumpstats();
    logstats(0);
    if (statsfile)
      dumpstats_z();
#endif
    exit(0);
  }
#ifndef NO_STATS
  if (signalled & SIGNALLED_SSTATS && statsfile)
    dumpstats();
  if (signalled & SIGNALLED_LSTATS) {
    logstats(signalled & SIGNALLED_ZSTATS);
    if (signalled & SIGNALLED_ZSTATS && statsfile)
      dumpstats_z();
  }
#endif
  if (signalled & SIGNALLED_RELOG)
    reopenlog();
  if (signalled & SIGNALLED_RELOAD)
    do_reload(fork_on_reload);
  signalled = 0;
  sigprocmask(SIG_SETMASK, &ssempty, NULL);
}

#ifndef NO_IPv6
static struct sockaddr_storage peer_sa;
#else
static struct sockaddr_in peer_sa;
#endif
static struct dnspacket pkt;

static void request(int fd) {
  int q, r;
  socklen_t salen = sizeof(peer_sa);

  q = recvfrom(fd, (void*)pkt.p_buf, sizeof(pkt.p_buf), 0,
               (struct sockaddr *)&peer_sa, &salen);
  if (q <= 0)			/* interrupted? */
    return;

  pkt.p_peerlen = salen;
  r = replypacket(&pkt, q, zonelist);
  if (!r)
    return;
  if (flog)
    logreply(&pkt, flog, flushlog);

  /* finally, send a reply */
  while(sendto(fd, (void*)pkt.p_buf, r, 0,
               (struct sockaddr *)&peer_sa, salen) < 0)
    if (errno != EINTR) break;

}

int main(int argc, char **argv) {
  init(argc, argv);
  setup_signals();
  reopenlog();
#ifdef HAVE_SETITIMER
  if (recheck) {
    struct itimerval itv;
    itv.it_interval.tv_sec  = itv.it_value.tv_sec  = recheck;
    itv.it_interval.tv_usec = itv.it_value.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &itv, NULL) < 0)
      error(errno, "unable to setitimer()");
  }
#else
  alarm(recheck);
#endif
#ifndef NO_STATS
  stats_time = time(NULL);
  if (statsfile)
    dumpstats_z();
#endif

  pkt.p_peer = (struct sockaddr *)&peer_sa;

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
#ifdef NO_POLL
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
#else /* !NO_POLL */
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
#endif /* NO_POLL */
  }
}

void oom(void) {
  if (initialized)
    dslog(LOG_ERR, 0, "out of memory loading dataset");
  else
    error(0, "out of memory");
}
