/* $Id$
 * dns_findcode() is an auxilary routine to find given code in a
 * given dns_codetab table.
 */

#include "dns.h"

const struct dns_nameval *
dns_findcode(const struct dns_codetab codes, int code) {
  const struct dns_nameval *nv;
  int a = 0, b = codes.count - 1, m;
  while(a <= b) {
    m = (a + b) >> 1;
    nv = codes.namevals + m;
    if (nv->val == code) return nv;
    if (nv->val < code) a = m + 1;
    else b = m - 1;
  }
  return 0;
}
