// Project the pinned parameter generator onto the sufficient metadata it reads.
// This process never calls the prover or claims acceptance of a payment.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "labrados_python.h"

static size_t raw_proof_bytes(const dch_pack_params params) {
    const struct _dch_params *front = params->pp_dch;
    const typeof(*params->pp_pack) *pack = params->pp_pack;
    size_t polzs = front->kappa_outer, jl_bytes = 0;
    for (size_t i = 0; i < pack->np; i++) {
        if (i == pack->zkround) {
            polzs += 4 * pack->zkp[0]->kappa_linfmsis + 256/N;
            continue;
        }
        const struct _lab_params *p = pack->p[i];
        if (p->compressed) polzs += 4*p->kappa[2];
        else if (p->tail) polzs += p->len[LAB_INCOM] + p->len[LAB_QUADG] + p->len[LAB_LIFT] + p->len[LAB_LING];
        else polzs += 2*p->kappa[1] + LIFTS;
        if (!p->compressed) jl_bytes += sizeof(((struct _lab_proof*)0)->p);
    }
    const struct _lab_params *last = pack->p[pack->np-1];
    if (!last->tail || last->compressed || !pack->zkp) exit(4);
    return polzs * sizeof(polz) + jl_bytes + last->fz * last->nmax * sizeof(poly);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    size_t vectors = strtoul(argv[1],NULL,10), products = strtoul(argv[2],NULL,10);
    if (vectors<2 || vectors>2000000 || !products || products>200000) return 2;
    size_t *n = calloc(vectors,sizeof(*n));
    uint64_t *bounds = calloc(vectors,sizeof(*bounds)), *req = calloc(vectors,sizeof(*req));
    normtype *types = calloc(vectors,sizeof(*types));
    if (!n || !bounds || !req || !types) return 3;
    for (size_t i=0; i<vectors; i++) { n[i]=1; bounds[i]=N; types[i]=BIN; }
    statement st;
    py_init_statement(st,vectors,n,bounds,req,types,1,0,0);
    free(n); free(bounds); free(req); free(types);
    int64_t unit=1, zero[N]={0};
    size_t first=0,second=1;
    // All quadratic metadata has rank one, binary length one and unit coefficient.
    if (py_append_quadratic(st,0,1,NULL,&first,&second,NULL,1,&unit,NULL,zero)) return 3;
    sparsecnst *original=st->rqcnst->sparse;
    sparsecnst *templates=aligned_alloc(_Alignof(sparsecnst),products*sizeof(*templates));
    if (!templates) return 3;
    for (size_t i=0;i<products;i++) memcpy(templates+i,original,sizeof(*templates));
    st->rqcnst->nsparse=products;
    st->rqcnst->sparse=templates;
    dch_pack_params pp;
    int ret=py_gen_params(pp,st,1,0);
    if (ret==0) {
        printf("field_arrays_B=%zu rounds=%zu zk_round=%zu\n",raw_proof_bytes(pp),pp->pp_pack->np,pp->pp_pack->zkround);
        py_free_params(pp);
    }
    st->rqcnst->sparse=original;
    st->rqcnst->nsparse=1;
    free(templates);
    py_free_statement(st);
    return ret;
}
