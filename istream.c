/* Simple and efficient (especially line-oriented) read (input)
 * stream implementation a-la stdio.
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "config.h"
#ifndef NO_ZLIB
#include <stdlib.h>
#include <zlib.h>
#endif
#include "istream.h"

#ifndef EPROTO
# define EPROTO ENOEXEC
#endif

#if !defined(__GNUC__) && !defined(__attribute__)
# define __attribute__(x)
#endif
#ifndef UNUSED
# define UNUSED __attribute__((unused))
#endif

/* An attempt of efficient copy-less way to read lines from a file.
 * We fill in a buffer, and try to find next newline character.
 * If found, advance 'readp' pointer past it, replace it with
 * null byte and return previous value of 'readp' (which points
 * to the beginning of the line).  When there's no newline found
 * in the data which is already read into buffer, there are several
 * possibilities:
 *  o the amount of data in buffer exceeds BUFSIZE/2 - line is too long,
 *    return whatever we have already.
 *  o we have at least BUFSIZE/2 free bytes at the end of the buffer -
 *    read next BUFSIZE/2 chunk from file (actual read may return less
 *    data)
 *  o we don't have BUFSIZE/2 free bytes at the end of the buffer -
 *    move some data to the beginning, to "defragment" the buffer,
 *    and start over.
 * We read in chunks of BUFSIZE/2, and the buffer size is BUFSIZE to
 * be able to avoid moving data in the buffer as much as possible,
 * AND to be able to read chunks of exactly BUFSIZE/2 size from the file,
 * to make i/o more efficient.
 */

int istream_getline(struct istream *sp, char **linep, char delim) {
  unsigned char *x, *s;
  int r;

  s = sp->readp;
  *linep = (char*)s;
  for (;;) {

    /* check if we already have complete line in the buffer */
    if (sp->readp < sp->endp &&
        (x = memchr(sp->readp, delim, sp->endp - sp->readp)))
      /* yes we have, just return it */
      return (sp->readp = x + 1) - s;

    sp->readp = sp->endp;

    /* check if the line is too long, and return it as well if it is */
    if ((unsigned)(sp->endp - s) >= ISTREAM_BUFSIZE/2)
      return sp->endp - s;

    /* if we've a 'gap' at the beginning, close it */
    if (s != sp->buf) {
      if (!(sp->endp - s)) {
        s = sp->readp = sp->endp = sp->buf;
        *linep = (char*)s;
      }
      else if (sp->endp > sp->buf + ISTREAM_BUFSIZE/2) {
        /* if too few bytes free */
        memmove(sp->buf, s, sp->endp - s);
        sp->endp  -= s - sp->buf;
        sp->readp = sp->endp;
        s = sp->buf;
        *linep = (char*)s;
      }
    }

    /* read the next chunk. read 2buf if at the beginning of buf */
    r = sp->readfn(sp, sp->endp, ISTREAM_BUFSIZE - (sp->endp - sp->buf),
                   sp->endp == sp->buf ? ISTREAM_BUFSIZE : ISTREAM_BUFSIZE/2);
    if (r <= 0)
      return r < 0 ? r : sp->readp - s;
    sp->endp += r;
  }
}

/* try to fill in a buffer if it contains less than BUFSIZE/2 bytes */
int istream_fillbuf(struct istream *sp) {
  if ((unsigned)(sp->endp - sp->readp) < ISTREAM_BUFSIZE/2) {
    int r;
    /* if we've a 'gap' at the beginning, close it */
    if (sp->readp != sp->buf) {
      if (!(sp->endp - sp->readp))
        sp->readp = sp->endp = sp->buf;
      else if (sp->endp > sp->buf + ISTREAM_BUFSIZE/2) {
        /* if too few bytes free */
        memmove(sp->buf, sp->readp, sp->endp - sp->readp);
        sp->endp  -= sp->readp - sp->buf;
        sp->readp = sp->buf;
      }
    }
    r = sp->readfn(sp, sp->endp, ISTREAM_BUFSIZE - (sp->endp - sp->buf),
                   sp->endp == sp->buf ? ISTREAM_BUFSIZE : ISTREAM_BUFSIZE/2);
    if (r <= 0)
      return r;
    sp->endp += r;
  }
  return sp->endp - sp->readp;
}

/* Try to read at least nbytes (BUFSIZE/2 max) from the file.
 * return nbytes (>0) if ok, 0 if less than nbytes read (EOF),
 * or <0 on error.
 */
int istream_ensurebytes(struct istream *sp, int nbytes) {
  int r;
  if (nbytes > ISTREAM_BUFSIZE/2)
    nbytes = ISTREAM_BUFSIZE/2;
  while (sp->endp - sp->readp < nbytes)
    if ((r = istream_fillbuf(sp)) <= 0)
      return r;
  return nbytes;
}

static int
istream_readfn(struct istream *sp, unsigned char *buf,
               int UNUSED size, int szhint) {
  return read((int)(long)sp->cookie, buf, szhint);
}

void istream_init(struct istream *sp,
                  int (*readfn)(struct istream*,unsigned char*,int,int),
                  void (*freefn)(struct istream*), void *cookie) {
  sp->cookie = cookie;
  sp->readfn = readfn;
  sp->freefn = freefn;
  sp->readp = sp->endp = sp->buf;
}

void istream_destroy(struct istream *sp) {
  if (sp->freefn)
    sp->freefn(sp);
  memset(sp, 0, sizeof(*sp));
}

void istream_init_fd(struct istream *sp, int fd) {
  istream_init(sp, istream_readfn, NULL, (void*)(long)fd);
}

/* check for gzip magic (2 bytes) */
int istream_compressed(struct istream *sp) {
  if (istream_ensurebytes(sp, 2) <= 0)
    return 0;
  if (sp->readp[0] != 0x1f || sp->readp[1] != 0x8b)
    return 0;
  return 1;
}

#ifndef NO_ZLIB

struct zistream {
  struct istream is;
  z_stream zs;
  unsigned crc32;
  unsigned bytes;
};

#define HEAD_CRC     0x02 /* bit 1 set: header CRC present */
#define EXTRA_FIELD  0x04 /* bit 2 set: extra field present */
#define ORIG_NAME    0x08 /* bit 3 set: original file name present */
#define COMMENT      0x10 /* bit 4 set: file comment present */
#define RESERVED     0xE0 /* bits 5..7: reserved */

/* always return end-of-file */
static int
istream_eof(struct istream UNUSED *sp, unsigned char UNUSED *buf,
            int UNUSED size, int UNUSED szhint) {
  return 0;
}

static int
zistream_readfn(struct istream *sp, unsigned char *buf,
                int size, int UNUSED szhint) {
  struct zistream *zsp = sp->cookie;
  int r = Z_OK;
  unsigned char *p;

  zsp->zs.next_out = buf;
  zsp->zs.avail_out = size;

  while(r == Z_OK && zsp->zs.avail_out != 0) {
    if (zsp->is.readp == zsp->is.endp) {
      r = istream_fillbuf(&zsp->is);
      if (r <= 0) {
        if (size != (int)zsp->zs.avail_out)
          r = Z_OK;
        else {
          if (!r) errno = EPROTO;
          r = Z_ERRNO;
        }
        break;
      }
    }
    zsp->zs.next_in = zsp->is.readp;
    zsp->zs.avail_in = zsp->is.endp - zsp->is.readp;
    r = inflate(&zsp->zs, Z_NO_FLUSH);
    zsp->is.readp = zsp->zs.next_in;
  }
  size -= zsp->zs.avail_out;
  zsp->bytes += size;
  zsp->crc32 = crc32(zsp->crc32, buf, size);

  switch(r) {
    case Z_STREAM_END:
      break;
    case Z_OK:
      return size;
    case Z_MEM_ERROR:
      errno = ENOMEM;
      return -1;
    default:
      errno = EPROTO;
    case Z_ERRNO:
      return -1;
  }

  inflateEnd(&zsp->zs);
  sp->readfn = istream_eof;
  r = istream_ensurebytes(&zsp->is, 8);  /* 8 bytes trailer */
  if (r <= 0) {
    if (!r)
      errno = EPROTO;
    return -1;
  }
  p = zsp->is.readp;
  zsp->is.readp += 8;
  if ((((unsigned)p[0] <<  0) |
       ((unsigned)p[1] <<  8) |
       ((unsigned)p[2] << 16) |
       ((unsigned)p[3] << 24)) != zsp->crc32 ||
      (((unsigned)p[4] <<  0) |
       ((unsigned)p[5] <<  8) |
       ((unsigned)p[6] << 16) |
       ((unsigned)p[7] << 24)) != (zsp->bytes & 0xffffffffu)) {
    errno = EPROTO;
    return -1;
  }
  return size;
}

static void zistream_freefn(struct istream *sp) {
  struct zistream *zsp = sp->cookie;
  inflateEnd(&zsp->zs);
  istream_destroy(&zsp->is);
  free(zsp);
}

int istream_uncompress_setup(struct istream *sp) {
  int r, x, flags;
  struct zistream *zsp;

  if (!istream_compressed(sp))
    return 0;

  sp->readp += 2;
  errno = EPROTO;
  if (istream_ensurebytes(sp, 8) <= 0)
    return -1;
  if (sp->readp[0] != Z_DEFLATED ||
      (flags = sp->readp[1]) & RESERVED)
    return -1;
  sp->readp += 8;
  if (flags & EXTRA_FIELD) {
    if (istream_ensurebytes(sp, 2) <= 0)
      return -1;
    x = sp->readp[0] | ((unsigned)sp->readp[1] << 8);
    sp->readp += 2;
    while(sp->endp - sp->readp < x) {
      x -= sp->endp - sp->readp;
      sp->readp = sp->endp;
      if (istream_fillbuf(sp) <= 0)
        return -1;
    }
    sp->readp += x;
  }
  x = ((flags & ORIG_NAME) ? 1 : 0) + ((flags & COMMENT) ? 1 : 0);
  while(x--) {
    char *p;
    do
      if ((r = istream_getline(sp, &p, '\0')) <= 0)
        return -1;
    while (p[r-1] != '\0');
  }
  if (flags & HEAD_CRC) {
    if (istream_ensurebytes(sp, 2) <= 0)
      return -1;
    sp->readp += 2;
  }

  zsp = malloc(sizeof(*zsp));
  if (!zsp) {
    errno = ENOMEM;
    return -1;
  }
  zsp->is.cookie = sp->cookie;
  zsp->is.readfn = sp->readfn;
  zsp->is.freefn = sp->freefn;
  x = sp->endp - sp->readp;
  memcpy(zsp->is.buf, sp->readp, x);
  zsp->is.readp = zsp->is.buf;
  zsp->is.endp = zsp->is.buf + x;
  zsp->zs.zalloc = NULL;
  zsp->zs.zfree = NULL;
  zsp->zs.opaque = NULL;
  zsp->bytes = 0;
  zsp->crc32 = crc32(0, NULL, 0);

  zsp->zs.next_in = zsp->is.readp;
  zsp->zs.avail_in = x;
  r = inflateInit2(&zsp->zs, -MAX_WBITS);
  switch(r) {
  case Z_OK:
    zsp->is.readp = zsp->zs.next_in;
    istream_init(sp, zistream_readfn, zistream_freefn, zsp);
    return 1;
  case Z_MEM_ERROR: errno = ENOMEM; break;
  case Z_ERRNO: break;
  default: errno = EPROTO; break;
  }
  inflateEnd(&zsp->zs);
  free(zsp);
  return -1;
}

#else /* !ZLIB */

int istream_uncompress_setup(struct istream *sp) {
  if (!istream_compressed(sp))
    return 0;
  errno = ENOSYS;
  return -1;
}

#endif

#ifdef TEST
#include <stdio.h>

int main() {
  struct istream is;
  char *l;
  int r;

  istream_init_fd(&is, 0);
  if (zistream_setup(&is) < 0) {
    perror("zistream_setup");
    return 1;
  }

  while((r = istream_getline(&is, &l, '\n')) > 0) {
#if 0
    printf("%d ", r);
    fwrite(l, r, 1, stdout);
    if (l[r-1] != '\n')
      printf(" (incomplete)\n");
#endif
#if 0
    write(1, l, r);
#endif
#if 1
    fwrite(l, r, 1, stdout);
#endif
  }

  if (r < 0)
    perror("read");

  return 0;
}
#endif
