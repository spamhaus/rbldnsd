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

#include "rbldnsd.h"
#include "dns.h"
#include "mempool.h"

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

unsigned defttl = 2048;		/* default record TTL */
static int recheck = 60;	/* interval between checks for reload */
static int accept_in_cidr;	/* accept 127.0.0.1/8-style CIDRs */
static int initialized;		/* 1 when initialized */
static char *logfile;		/* log file name */

static int satoi(const char *s) {
  int n = 0;
  if (*s < '0' || *s > '9') return -1;
  do n = n * 10 + (*s++ - '0');
  while (*s >= '0' && *s <= '9');
  return *s ? -1 : n;
}

static void NORETURN usage(int exitcode) {
   printf(
"%s: rbl dns daemon version " VERSION "\n"
"Usage is: %s [options] zone...\n"
"where options are:\n"
" -u user[:group] - run as this user:group (rbldns)\n"
" -r rootdir - chroot to this directory\n"
" -w workdir - working directory with zone files\n"
" -b [address][:port] - bind to (listen on) this address (*:53)\n"
" -t ttl - TTL value set in answers (2048)\n"
" -e - enable CIDR ranges where prefix is not on the range boundary\n"
"  (by default ranges such 127.0.0.1/8 will be rejected)\n"
" -c check - check for file updates every `check' secs (60)\n"
" -p pidfile - write backgrounded pid to specified file\n"
" -n - do not become a daemon\n"
" -l logfile - log queries and answers to this file\n"
"  (relative to chroot directory)\n"
"each zone specified using `name:type:file,file...'\n"
"syntax, repeated names constitute the same zone.\n"
"Available zone types:\n"
, progname, progname);
  printzonetypes(stdout);
  exit(exitcode);
}

static int init(int argc, char **argv, struct zone **zonep) {
  int c;
  char *p;
  char *user = "rbldns", *bindaddr = "";
  char *root = NULL, *workdir = NULL, *pidfile = NULL;
  FILE *fpid = NULL;
  uid_t uid = 0;
  gid_t gid = 0;
  struct sockaddr_in sin;
  ip4addr_t saddr;
  int fd;
  int nodaemon = 0;

  if ((progname = strrchr(argv[0], '/')) != NULL)
    argv[0] = ++progname;
  else
    progname = argv[0];

  if (argc <= 1) usage(1);

  while((c = getopt(argc, argv, "u:r:b:w:t:c:p:nel:h")) != EOF)
    switch(c) {
    case 'u': user = optarg; break;
    case 'r': root = optarg; break;
    case 'b': bindaddr = optarg; break;
    case 'w': workdir = optarg; break;
    case 'p': pidfile = optarg; break;
    case 't':
      if ((c = satoi(optarg)) < 0)
        error(0, "invalid ttl (-t) value `%.50s'", optarg);
      defttl = c;
      break;
    case 'c':
      if ((c = satoi(optarg)) < 0)
        error(0, "invalid check interval (-c) value `%.50s'", optarg);
      recheck = c;
      break;
    case 'n': nodaemon = 1; break;
    case 'e': accept_in_cidr = 1; break;
    case 'l': logfile = optarg; break;
    case 'h': usage(0);
    default: error(0, "type `%.50s -h' for help", progname);
    }

  if (!(argc -= optind))
    error(0, "no zone(s) to service specified (-h for help)");
  argv += optind;

  if (nodaemon)
    logto = LOGTO_STDOUT;
  else {
    tzset();
    openlog(progname, LOG_PID|LOG_NDELAY, LOG_DAEMON);
    logto = LOGTO_STDOUT | LOGTO_SYSLOG;
  }

  fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0)
    error(errno, "unable to create listening socket");
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  if (bindaddr) {
    if ((p = strchr(bindaddr, ':')) != NULL)
      *p++ = '\0';
    if (*bindaddr && ip4addr(bindaddr, &saddr, NULL))
      sin.sin_addr.s_addr = htonl(saddr);
    else {
      struct hostent *he = gethostbyname(bindaddr);
      if (!he)
        error(0, "invalid bind address specified: `%.50s'", bindaddr);
      if (he->h_addrtype != AF_INET || he->h_length != sizeof(sin.sin_addr))
        error(0, "unexpected type of listening address `%.50s'", bindaddr);
      memcpy(&sin.sin_addr, he->h_addr_list[0], sizeof(sin.sin_addr));
      saddr = ntohl(sin.sin_addr.s_addr);
      endhostent();
    }
  }
  else {
    p = NULL;
    saddr = 0;
  }
  if (p && *p) {
    if ((c = satoi(p)) > 0)
      ;
    else {
      struct servent *se = getservbyname(p, "udp");
      if (!se)
        error(0, "%.50s/udp: unknown service", p);
      c = se->s_port;
      endservent();
    }
    p[-1] = ':';
  }
  else
    c = DNS_PORT;
  sin.sin_port = htons(c);
  if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    error(errno, "unable to bind to %s:%d", ip4atos(saddr), c);

  c = 65536;
  do
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &c, sizeof c) == 0)
      break;
  while ((c -= (c >> 5)) >= 1024);

  if ((p = strchr(user, ':')) != NULL)
    *p++ = '\0';
  if ((c = satoi(user)) >= 0)
    uid = c, gid = c;
  else {
    struct passwd *pw = getpwnam(user);
    if (!pw)
      error(0, "invalid user `%.50s' specified", user);
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
        error(0, "invalid group `%.50s' specified", p);
      gid = gr->gr_gid;
      endgrent();
    }
    p[-1] = ':';
  }

  if (pidfile && (fpid = fopen(pidfile, "w")) == NULL)
    error(errno, "unable to write pidfile");

  if (root && (chdir(root) < 0 || chroot(root) < 0))
    error(errno, "unable to chroot");
  if (workdir && chdir(workdir) < 0)
    error(errno, "unable to chdir to %.50s", workdir);

  if (setgroups(1, &gid) < 0 || setgid(gid) < 0 || setuid(uid) < 0)
    error(errno, "unable to setuid(%d:%d)", uid, gid);

  *zonep = NULL;
  for(c = 0; c < argc; ++c)
    *zonep = addzone(*zonep, argv[c]);

  if (!reloadzones(*zonep))
    error(0, "zone loading errors, aborting");
  initialized = 1;
  zlog(LOG_INFO, 0, "started");

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

  return fd;
}

static volatile int want_reload;

static void sighandler(int sig) {
  switch(sig) {
  case SIGALRM:
    alarm(recheck);
    want_reload = 1;
    break;
  case SIGHUP:
    want_reload = 2;
    break;
  case SIGTERM:
  case SIGINT:
    zlog(LOG_INFO, 0, "terminating");
    exit(0);
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
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
}

int main(int argc, char **argv) {
  int fd;
  struct zone *zonelist;
  FILE *flog;
  fd = init(argc, argv, &zonelist);
  flog = logfile ? fopen(logfile, "a") : NULL;
  setup_signals();
  alarm(recheck);
  for(;;) {
    if (want_reload) {
      sigset_t ssorig;
      sigprocmask(SIG_BLOCK, &ssblock, &ssorig);
      reloadzones(zonelist);
      if (want_reload > 1 && logfile) {
	if (flog) fclose(flog);
	flog = fopen(logfile, "a");
      }
      want_reload = 0;
      sigprocmask(SIG_SETMASK, &ssorig, NULL);
    }
    udp_request(fd, zonelist, flog);
  }
  return 0;
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
  if (bits && !accept_in_cidr && (*a1p & ~ip4mask(bits)))
    return 0;
  return 1;
}

void oom() {
  if (initialized)
    zlog(LOG_ERR, 0, "out of memory loading zone (zone will be empty)");
  else
    error(0, "out of memory");
}
