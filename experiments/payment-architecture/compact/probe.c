/* Disposable MP10 wallet. Only public inputs and completed authorizations leave the process. */
#include "fastrandombytes.h"
#include "keygen.h"
#include "mint.h"
#include "randombytes.h"
#include "sammat.h"
#include "setup.h"
#include "spend.h"
#include "verify.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static POLY_Q m1[K+3][N], m2[K][3];
static POLY_QHAT m3[K_HAT+2*N_SPENT+4][N_HAT];
static unsigned char pp[CRYPTO_BYTES];

typedef struct {
    ACT members[N_SPENT][M];
    PK_OUT keys[S];
    CN_OUT coins[S];
    SN_OUT serial[M];
    SPEND_OUT proof;
} Public;

/* The two inputs are genuinely opened. Mint and KeyGen create the decoys independently. */
static void new_account(ACT *coin, ASK *own, uint64_t amount, int new_key) {
    uint64_t bits[R];
    if (new_key) keygen(coin->pk,own->sk,own->sn,m1);
    mint(coin->cn,own->ck,bits,amount,m1,m2);
    own->amt_in = amount;
}

static void prove(void) {
    static Public tx;
    static ACT real[M];
    static ASK own[M], unused;
    unsigned char randomness[CRYPTO_BYTES];
    randombytes(randomness,sizeof(randomness));
    fastrandombytes_setseed_prv(randomness);
    new_account(&real[0],&own[0],61,1);
    new_account(&real[1],&own[1],39,1);
    POLY_R dest_secret[N_BAR+K];
    unsigned char dest_serial[CRYPTO_BYTES];
    for (size_t j=0;j<S;j++) keygen(tx.keys[j].pk,dest_secret,dest_serial,m1);
    for (size_t attempt=0;attempt<3;attempt++) {
        unsigned char sampled;
        do { randombytes(&sampled,1); } while (sampled >= 250);
        size_t pos = sampled % N_SPENT;
        if (attempt==2) {
            new_account(&real[0],&own[0],71,0);
            new_account(&real[1],&own[1],29,0);
        }
        for (size_t row=0;row<N_SPENT;row++) {
            for (size_t j=0;j<M;j++) {
                if (row==pos) tx.members[row][j]=real[j];
                else new_account(&tx.members[row][j],&unused,53+9*j,1);
            }
        }
        CK_OUT confidential_openings[S];
        uint64_t amounts[S]={17,83};
        spend(&tx.proof,tx.coins,confidential_openings,tx.serial,tx.members,pos,own,tx.keys,amounts,m1,m2,m3,pp);
        if (fwrite(&tx,sizeof(tx),1,stdout)!=1) exit(3);
    }
}

int main(int argc,char **argv) {
    unsigned char public_seed[32]="payment-architecture/MP10/v1";
    fastrandombytes_setseed_pub(public_seed);
    setup(pp,public_seed);
    sample_mat1(m1); sample_mat2(m2); sample_mat3(m3);
    if (argc!=2) return 2;
    if (!strcmp(argv[1],"prove")) { prove(); return 0; }
    if (!strcmp(argv[1],"verify")) {
        static Public tx;
        if (fread(&tx,sizeof(tx),1,stdin)!=1 || getchar()!=EOF) return 3;
        return verify(tx.members,tx.keys,tx.coins,tx.serial,&tx.proof,m1,m2,m3,pp)==1 ? 0 : 1;
    }
    return 2;
}
