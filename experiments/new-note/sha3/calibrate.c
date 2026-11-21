/* Component calibration for the Boolean Keccak-f circuit, using public inputs. */
#define _POSIX_C_SOURCE 200809L
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { PARTIES = 3, LANES = 25, WORDS = 24*LANES, TRIALS = 1024 };
typedef uint64_t state[PARTIES][LANES];
typedef uint64_t views[PARTIES][WORDS];
static const uint64_t rc[24] = {
  1,0x8082,0x800000000000808aULL,0x8000000080008000ULL,0x808b,0x80000001,
  0x8000000080008081ULL,0x8000000000008009ULL,0x8a,0x88,0x80008009,0x8000000a,
  0x8000808b,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
  0x8000000000008002ULL,0x8000000000000080ULL,0x800a,0x800000008000000aULL,
  0x8000000080008081ULL,0x8000000000008080ULL,0x80000001,0x8000000080008008ULL
};
static const unsigned rot[25] = {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};

static uint64_t rol(uint64_t a, unsigned n) { return (a << n) | (a >> ((64-n)&63)); }
static void linear(uint64_t b[25], const uint64_t a[25]) {
    uint64_t c[5], d[5];
    for (int x=0; x<5; x++) c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
    for (int x=0; x<5; x++) d[x]=c[(x+4)%5]^rol(c[(x+1)%5],1);
    for (int y=0;y<5;y++) for (int x=0;x<5;x++) {
        int i=x+5*y;
        b[y+5*((2*x+3*y)%5)]=rol(a[i]^d[x],rot[i]);
    }
}
static void simulate(state a, const views tape, views transcript) {
    state b;
    for (int t=0;t<24;t++) {
        for(int j=0;j<3;j++) linear(b[j],a[j]);
        for(int y=0;y<5;y++) for(int x=0;x<5;x++) {
            int i=5*y+x, k=5*y+(x+1)%5, m=5*y+(x+2)%5, o=t*25+i;
            uint64_t u[3]={~b[0][k],b[1][k],b[2][k]};
            for(int j=0;j<3;j++) {
                int n=(j+1)%3;
                uint64_t z=(u[j]&b[j][m])^(u[n]&b[j][m])^(u[j]&b[n][m])^tape[j][o]^tape[n][o];
                transcript[j][o]=z;
                a[j][i]=b[j][i]^z;
            }
        }
        a[0][0]^=rc[t];
    }
}
/* Check views 0,1. All challenge orientations have the same operations. */
static uint64_t check(state a, const views tape, const views transcript) {
    uint64_t bad=0, b[2][25];
    for(int t=0;t<24;t++) {
        for(int j=0;j<2;j++) linear(b[j],a[j]);
        for(int y=0;y<5;y++) for(int x=0;x<5;x++) {
            int i=5*y+x,k=5*y+(x+1)%5,m=5*y+(x+2)%5,o=t*25+i;
            uint64_t z=((~b[0][k])&b[0][m])^(b[1][k]&b[0][m])^((~b[0][k])&b[1][m])^tape[0][o]^tape[1][o];
            bad|=z^transcript[0][o];
            for(int j=0;j<2;j++) a[j][i]=b[j][i]^transcript[j][o];
        }
        a[0][0]^=rc[t];
    }
    return bad;
}
static double cpu(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID,&t)) exit(2);
    return t.tv_sec+t.tv_nsec*1e-9;
}
static volatile uint64_t run_sink;
static void bulk(const EVP_MD *md, const char *label, int xof) {
    enum { LENGTH=512*1024, ROUNDS=16 };
    static unsigned char area[LENGTH];
    unsigned char digest[64];
    double start=cpu();
    for(unsigned k=0;k<ROUNDS;k++) {
        EVP_MD_CTX *ctx=EVP_MD_CTX_new();
        if(!ctx || !EVP_DigestInit_ex(ctx,md,NULL)) exit(1);
        if(xof) {
            if(!EVP_DigestUpdate(ctx,&k,sizeof(k)) || !EVP_DigestFinalXOF(ctx,area,LENGTH)) exit(1);
            run_sink^=area[k];
        } else {
            area[0]=(unsigned char)k;
            if(!EVP_DigestUpdate(ctx,area,LENGTH) || !EVP_DigestFinal_ex(ctx,digest,NULL)) exit(1);
            run_sink^=digest[0];
        }
        EVP_MD_CTX_free(ctx);
    }
    printf("%s %.2f\n",label,LENGTH*(double)ROUNDS/(cpu()-start));
}
int main(void) {
    state start={0}, a;
    views tape, transcript;
    uint16_t endian=1;
    if(*(unsigned char*)&endian!=1) return 2;
    for(int j=0;j<3;j++) for(int i=0;i<WORDS;i++)
        tape[j][i]=(0x9e3779b97f4a7c15ULL*(1+i+WORDS*j))^rol((unsigned)(i+j),7);
    for(int i=0;i<LANES;i++) {
        start[1][i]=tape[1][i];
        start[2][i]=tape[2][i];
        start[0][i]=start[1][i]^start[2][i];
    }
    /* One padded empty SHA3-384 block, 104-byte rate, verified via OpenSSL. */
    start[0][0]^=6;
    start[0][12]^=0x8000000000000000ULL;
    memcpy(a,start,sizeof(a)); simulate(a,tape,transcript);
    unsigned char digest[EVP_MAX_MD_SIZE];
    if(!EVP_Digest("",0,digest,NULL,EVP_sha3_384(),NULL)) return 2;
    for(int i=0;i<6;i++) {
        uint64_t recovered=a[0][i]^a[1][i]^a[2][i];
        if(memcmp(&recovered,digest+8*i,8)) return 1;
    }
    memcpy(a,start,sizeof(a)); if(check(a,tape,transcript)) return 1;
    transcript[0][3]^=1;
    memcpy(a,start,sizeof(a)); if(!check(a,tape,transcript)) return 1;
    transcript[0][3]^=1;
    double begin=cpu();
    for(int t=0;t<TRIALS;t++) {
        memcpy(a,start,sizeof(a)); a[0][0]^=(uint64_t)t;
        simulate(a,tape,transcript);
        run_sink^=transcript[t%3][t%WORDS];
    }
    printf("prover_cpu_ns_per_keccak_f %.2f\n",(cpu()-begin)*1e9/TRIALS);
    begin=cpu();
    for(int t=0;t<TRIALS;t++) {
        memcpy(a,start,sizeof(a)); a[0][0]^=(uint64_t)t;
        run_sink^=check(a,tape,transcript);
    }
    printf("verifier_cpu_ns_per_keccak_f %.2f\n",(cpu()-begin)*1e9/TRIALS);
    bulk(EVP_shake256(),"shake256_tape_B_per_cpu_s",1);
    bulk(EVP_sha3_512(),"sha3_512_view_B_per_cpu_s",0);
    return 0;
}
