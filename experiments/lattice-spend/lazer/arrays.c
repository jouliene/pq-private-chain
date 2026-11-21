// Research fixture codec for the pinned 38-bit, N=256, ZK membership profiles.
// Only coefficient arrays consumed by the verifier are encoded. Sizes and
// pointer offsets originate from locally generated parameters on either end.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dachshund.h"

_Static_assert(sizeof(poly) == 512 && sizeof(polz) == 3 * 512, "unexpected ABI");
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error little-endian fixture representation
#endif
#define LIMIT (1024u * 1024u)

struct stream {
  uint8_t *buf;
  size_t size;
  size_t pos;
  int read;
};

static int block(struct stream *s, void *ptr, size_t bytes) {
  if (bytes > s->size - s->pos || !ptr) return 0;
  if (s->read) memcpy(ptr, s->buf + s->pos, bytes);
  else memcpy(s->buf + s->pos, ptr, bytes);
  s->pos += bytes;
  return 1;
}

static int polynomials(struct stream *s, polz **base, size_t number) {
  if (!number || number > LIMIT / sizeof(polz)) return 0;
  if (s->read) *base = aligned_alloc(64, number * sizeof(polz));
  return block(s, *base, number * sizeof(polz));
}

int fixture_arrays(dch_pack_params params, dch_pack_proof packet,
                   uint8_t *buf, size_t size, int read) {
  if (!buf || size > LIMIT) return -1;
  struct stream s = {buf, size, 0, read};
  struct _dch_params *d = params->pp_dch;
  const typeof(*params->pp_pack) *p = params->pp_pack;
  typeof(*packet->pi_pack) *out = packet->pi_pack;
  // Restrict to the tested ZK frontend. All allocation sizes here are public.
  if (!d->nquad || !p->zkp || p->np < 3 || p->np > 20 ||
      p->zkround >= p->np - 1 || !p->p[p->np-1]->tail) return -1;
  if (read) {
    out->np = p->np;
    out->p = calloc(p->np, sizeof(lab_proof));
    out->zkp = calloc(1, sizeof(lnp_proof));
    if (!out->p || !out->zkp) return -1;
  }
  if (!polynomials(&s, &packet->pi_dch->com, d->kappa_outer)) return -1;
  for (size_t i = 0; i < p->np; i++) {
    if (i == p->zkround) {
      size_t k = p->zkp[0]->kappa_linfmsis;
      polz **m = out->zkp[0]->m;
      if (!polynomials(&s, m, 4*k + 256/N)) return -1;
      if (read) {
        m[1] = m[0]+k; m[2] = m[1]+k;
        m[3] = m[2]+256/N; m[4] = m[3]+k;
      }
      continue;
    }
    const struct _lab_params *q = p->p[i];
    struct _lab_proof *pi = out->p[i];
    // Sizes/offsets mirror lab_proof_init in labrador_core.c.
    size_t first, lift, rest;
    if (q->compressed) {
      first = 2*q->kappa[2]; lift = q->kappa[2]; rest = lift;
    } else if (q->tail) {
      first = q->len[LAB_INCOM] + q->len[LAB_QUADG];
      lift = q->len[LAB_LIFT]; rest = q->len[LAB_LING];
    } else {
      first = q->kappa[1]; lift = LIFTS; rest = first;
    }
    if (!polynomials(&s, pi->m, first+lift+rest)) return -1;
    if (read) {
      pi->m[1] = q->compressed ? pi->m[0]+q->kappa[2] : NULL;
      pi->m[2] = pi->m[0]+first; pi->m[3] = pi->m[2]+lift;
    }
    if (!q->compressed && !block(&s, pi->p, sizeof(pi->p))) return -1;
  }
  // The tested final tail sends the reduced polynomial opening itself. Its
  // public shape is exactly fz vectors with nmax polys each (lab_witness_init).
  const struct _lab_params *tail = p->p[p->np-1];
  size_t r = tail->fz, n = tail->nmax;
  if (tail->compressed || (r != 1 && r != 2) || !n || n > LIMIT/(r*sizeof(poly))) return -1;
  struct _witness *w = out->owt;
  if (read) {
    w->r = r;
    w->n = calloc(r, sizeof(size_t) + sizeof(poly*));
    if (!w->n) return -1;
    w->s = (poly **)(w->n+r);
    w->s[0] = aligned_alloc(64, n*r*sizeof(poly));
    if (!w->s[0]) return -1;
    for (size_t i=0;i<r;i++) {
      w->n[i]=n;
      w->s[i]=w->s[0]+n*i;
    }
  }
  if (w->r != r) return -1;
  for (size_t i=0;i<r;i++)
    if (w->n[i]!=n || !block(&s, w->s[i], n*sizeof(poly))) return -1;
  if (read && s.pos != size) return -1;
  return (int)s.pos;
}
