/* simple read (input) stream (header file)
 */

#ifndef ISTREAM_BUFSIZE

#define ISTREAM_BUFSIZE 65536	/* max line size is ISTREAM_BUFSIZE/2 */
#define ISTREAM_PAD 4		/* extra safety bytes */

struct istream {
  unsigned char *endp;	/* end-of-data pointer (data read so far) in buf */
  unsigned char *readp;	/* current read pointer within buf */
  unsigned char pad1[ISTREAM_PAD];
  unsigned char buf[ISTREAM_BUFSIZE]; /* the data pointer */
  unsigned char pad2[ISTREAM_PAD];
  void *cookie;		/* cookie for readfn routine */
  int  (*readfn)(struct istream *sp, unsigned char *buf, int size, int szhint);
  void (*freefn)(struct istream *sp);
};
#define istream_buf(sp) ((sp)->buf+ISTREAM_EXTRA)

int istream_fillbuf(struct istream *sp);
int istream_ensurebytes(struct istream *sp, int nbytes);
int istream_getline(struct istream *sp, char **linep, char delim);
void istream_init(struct istream *sp,
                  int (*readfn)(struct istream*,unsigned char*,int,int),
                  void (*freefn)(struct istream*), void *cookie);
void istream_init_fd(struct istream *sp, int fd);
void istream_destroy(struct istream *sp);

/* checks whenever the given stream is in gzip format */
int istream_compressed(struct istream *sp);
/* setup istream to automatically uncompress input if compressed */
int istream_uncompress_setup(struct istream *sp);

#endif /* include guard */
