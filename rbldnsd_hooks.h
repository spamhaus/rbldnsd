/* $Id$
 * hooks for rbldnsd
 * In certain places, rbldnsd will call various user-supplied routines
 * (implementation is in rbldnsd_hooks.c).
 * In order for rbldnsd to actually call the routine(s), implement necessary
 * hook_mumble() in rbldnsd_hooks.c and #define do_hook_mumble when building
 * the executable.
 */

/* a short string describing what's implemented in hooks
 * (with leading space) please */
extern const char *hook_info;

/* process options (-H parameters), return 0 if ok */
int hook_getopt(char *optarg);

/* initialize stuff after rest has been inited, return 0 if ok */
int hook_init(const struct zone *zonelist);

/* perform actual reload, after all zones has been reloaded.
 * should call start_loading() if it really needs to perform some
 * long operation, to allow background query processing while reloading */
int hook_reload(const struct zone *zonelist);

/* check whenever this query is allowed for this client:
 * 0 = ok, <0 = drop the packet, >0 = refuse */
int hook_query_access(const struct sockaddr *requestor,
                      const struct zone *zone,
                      const struct dnsqinfo *qinfo);
/* notice result of the OK query */
void hook_query_result(const struct sockaddr *requestor,
                       const struct zone *zone,
                       const struct dnsqinfo *qinfo,
                       int positive);

