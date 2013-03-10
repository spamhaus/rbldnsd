/* common #include header for various helper routines to
 * manipulate IP4 addreses
 */

#ifndef _IP4ADDR_H_INCLUDED
#define _IP4ADDR_H_INCLUDED

#include "config.h"

#if !defined(NO_STDINT_H)
# include <stdint.h>
typedef uint32_t ip4addr_t; /* host byte order */
#elif SIZEOF_SHORT == 4
typedef unsigned short ip4addr_t;
#else
typedef unsigned ip4addr_t;
#endif

/* parse string to ip4addr_t (if np specified, return
 * pointer to the next characted in it)...: */

/*  ..single address, like inet_aton/inet_addr,
 *    return #bits in _prefix_ (32,24,16 or 8) or <0 on error */
int ip4addr(const char *s, ip4addr_t *ap, char **np);

/*  ..prefix, 1.2.3.4 or 1.2.3 or 1.2, return number of bits or <0 */
int ip4prefix(const char *s, ip4addr_t *ap, char **np);

/*  ..CIDR range, return number of bits or <0 if error.
 *    does NOT zerofill hostpart of *ap - &= ip4mask(bits) for this */
int ip4cidr(const char *s, ip4addr_t *ap, char **np);

/*  ..range of addresses (inclusive) or CIDR, return #bits if
 *    that was CIDR or prefix or 32 if plain range, <0 on error.
 *    does NOT zerofill hostpart of *ap - &= ip4mask(bits) for this.
 *    *bp will be real end of range regardless of netmask */
int ip4range(const char *s, ip4addr_t *ap, ip4addr_t *bp, char **np);


/* inet_ntoa() */
const char *ip4atos(ip4addr_t a);

/* convert #bits into mask */
/* note: works for bits < 32 only! */
extern const ip4addr_t ip4addr_cidr_netmasks[33];
#define ip4mask(bits) ip4addr_cidr_netmasks[bits]

#define IP4A_LOOPBACK 0x7f000000


/* ip4unpack(bytes, a)
 *
 * Unpack ip4addr_t to an array of (four) bytes
 */
#ifndef inline /* compiler supports 'inline' */
static inline void
ip4unpack(unsigned char bytes[4], ip4addr_t a) {
  bytes[0] = (unsigned char)(a >> 24);
  bytes[1] = (unsigned char)(a >> 16);
  bytes[2] = (unsigned char)(a >> 8);
  bytes[3] = (unsigned char)a;
}
#else /* inline macro defined - compiler may not support 'inline' */
# define ip4unpack(bytes, a) ( bytes[0] = (unsigned char)(a >> 24),     \
                               bytes[1] = (unsigned char)(a >> 16),     \
                               bytes[2] = (unsigned char)(a >> 8),      \
                               bytes[3] = (unsigned char)a )
#endif

#endif
