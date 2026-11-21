/* Private FS01 leaf opening, compiled to the generic binary VOLE circuit API. */
#define _DEFAULT_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <openssl/evp.h>

#include "proof.h"
#include "fiat_shamir.h"

enum { MESSAGE_BYTES = 130, WITNESS_BYTES = 128, DIGEST_BYTES = 64 };
static const uint8_t domain[] = "fresh-spend/fs01-leaf/v1";
static const voleith_params_t *params;

static void require(int ok, const char *error) {
    if (!ok) {
        fprintf(stderr, "%s\n", error);
        exit(EXIT_FAILURE);
    }
}

static void random_bytes(uint8_t *buf, size_t len) {
    while (len != 0) {
        ssize_t n = getrandom(buf, len, 0);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "getrandom failed");
        buf += n;
        len -= (size_t)n;
    }
}

/* Lanes have index x+5*y and bits run LSB first, as in FIPS 202. */
typedef wire_id State[25][64];
static void permutation(voleith_circuit_t *c, State a) {
    static const unsigned rotations[25] = {
        0,1,62,28,27, 36,44,6,55,20, 3,10,43,25,39, 41,45,15,21,8, 18,2,61,56,14
    };
    uint8_t lfsr = 1;
    for (int round = 0; round < 24; ++round) {
        wire_id parity[5][64];
        for (int x = 0; x < 5; ++x)
            for (int z = 0; z < 64; ++z) {
                wire_id sum = a[x][z];
                for (int y = 1; y < 5; ++y) sum = voleith_circuit_add_xor(c, sum, a[x+5*y][z]);
                parity[x][z] = sum;
            }
        State b;
        for (int x = 0; x < 5; ++x)
            for (int z = 0; z < 64; ++z) {
                wire_id d = voleith_circuit_add_xor(c, parity[(x+4)%5][z], parity[(x+1)%5][(z+63)%64]);
                for (int y = 0; y < 5; ++y) {
                    int i = x + 5*y;
                    int target = y + 5*((2*x+3*y)%5);
                    b[target][(z+rotations[i])%64] = voleith_circuit_add_xor(c, a[i][z], d);
                }
            }
        for (int y = 0; y < 5; ++y)
            for (int x = 0; x < 5; ++x)
                for (int z = 0; z < 64; ++z) {
                    wire_id neg = voleith_circuit_add_not(c, b[(x+1)%5+5*y][z]);
                    wire_id ch = voleith_circuit_add_and(c, neg, b[(x+2)%5+5*y][z]);
                    a[x+5*y][z] = voleith_circuit_add_xor(c, b[x+5*y][z], ch);
                }
        for (unsigned j = 0; j < 7; ++j) {
            unsigned z = (1u << j) - 1;
            if (lfsr & 1) a[0][z] = voleith_circuit_add_not(c, a[0][z]);
            lfsr = (uint8_t)((lfsr << 1) ^ ((lfsr & 128) ? 0x71 : 0));
        }
    }
}

static voleith_circuit_t *build(void) {
    voleith_circuit_t *c = voleith_circuit_new();
    require(c != NULL, "circuit allocation failed");
    State a;
    uint8_t block[200] = {[0] = 0xf1, [1] = 5, [MESSAGE_BYTES] = 0x1f, [135] = 0x80};
    wire_id fixed[] = {voleith_circuit_add_const(c, 0), voleith_circuit_add_const(c, 1)};
    for (unsigned i = 0; i < 1600; ++i) {
        unsigned byte = i / 8;
        a[i/64][i%64] = (byte >= 2 && byte < MESSAGE_BYTES)
            ? voleith_circuit_add_witness(c) : fixed[(block[byte] >> (i%8)) & 1];
    }
    permutation(c, a);
    for (unsigned i = 0; i < 8 * DIGEST_BYTES; ++i)
        voleith_circuit_assert_equal(c, a[i/64][i%64], voleith_circuit_add_instance(c));
    require(voleith_circuit_ok(c) && voleith_circuit_validate(c) == 0, "invalid circuit");
    require(voleith_circuit_witness_count(c) == 1024 &&
            voleith_circuit_and_gate_count(c) == 38400, "unexpected geometry");
    return c;
}

static void prove(const voleith_circuit_t *c, size_t expected) {
    uint8_t w[WITNESS_BYTES], public_value[DIGEST_BYTES], coins[32];
    random_bytes(w, sizeof(w));
    random_bytes(coins, sizeof(coins));
    EVP_MD_CTX *hash = EVP_MD_CTX_new();
    const uint8_t tag[] = {0xf1, 5};
    require(hash && EVP_DigestInit_ex(hash, EVP_shake256(), NULL) &&
            EVP_DigestUpdate(hash, tag, sizeof(tag)) && EVP_DigestUpdate(hash, w, sizeof(w)) &&
            EVP_DigestFinalXOF(hash, public_value, sizeof(public_value)), "OpenSSL SHAKE256 failed");
    EVP_MD_CTX_free(hash);

    const size_t blob_len = voleith_commit_blob_size(params, c);
    uint8_t *blob = malloc(blob_len);
    require(blob != NULL, "blob allocation failed");
    voleith_prover_commit_t *ctx = NULL;
    require(voleith_prove_commit(&ctx, params, c, w, public_value,
                                 coins, sizeof(coins), blob) == 0, "commit failed");
    explicit_bzero(coins, sizeof(coins));

    /* Match the public verifier's H2_1 schedule; private coins were used only in H3. */
    uint8_t challenge[5 * 32 + 8];
    require(sizeof(challenge) == voleith_chall1_bytes(params->lambda), "challenge length");
    voleith_transcript_t t;
    voleith_transcript_init(&t, params->lambda, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, domain, sizeof(domain) - 1);
    voleith_transcript_absorb(&t, public_value, sizeof(public_value));
    voleith_transcript_absorb(&t, blob, blob_len);
    voleith_transcript_squeeze(&t, challenge, sizeof(challenge));
    voleith_transcript_clear(&t);
    free(blob);
    voleith_proof_t p = {0};
    require(voleith_prove_respond(&p, ctx, c, w, public_value, challenge) == 0, "prove failed");
    explicit_bzero(w, sizeof(w));
    voleith_prover_commit_free(ctx);
    require(p.len == expected, "proof geometry mismatch");
    require(fwrite(public_value, 1, sizeof(public_value), stdout) == sizeof(public_value) &&
            fwrite(p.data, 1, p.len, stdout) == p.len && fflush(stdout) == 0, "public output failed");
    voleith_proof_free(&p);
}

static void verify(const voleith_circuit_t *c, size_t expected, int controls) {
    uint8_t public_value[DIGEST_BYTES];
    voleith_proof_t p = {.len = expected, .data = malloc(expected)};
    require(p.data != NULL && fread(public_value, 1, sizeof(public_value), stdin) == sizeof(public_value) &&
            fread(p.data, 1, p.len, stdin) == p.len && fgetc(stdin) == EOF && !ferror(stdin), "invalid framing");
    require(voleith_verify_v2(&p, params, c, public_value, sizeof(public_value), domain, sizeof(domain) - 1) == 0,
            "public verify failed");
    if (!controls) {
        printf("accepted exact FS01 leaf; proof_bytes=%zu\n", p.len);
        voleith_proof_free(&p);
        return;
    }
    public_value[0] ^= 1;
    require(voleith_verify_v2(&p, params, c, public_value, sizeof(public_value), domain, sizeof(domain) - 1) != 0,
            "changed statement accepted");
    public_value[0] ^= 1;
    require(voleith_verify_v2(&p, params, c, public_value, sizeof(public_value), domain, sizeof(domain) - 2) != 0,
            "changed transcript context accepted");
    p.data[p.len - 1] ^= 1;
    require(voleith_verify_v2(&p, params, c, public_value, sizeof(public_value), domain, sizeof(domain) - 1) != 0,
            "changed proof accepted");
    printf("accepted fresh component, rejected changed statement, context and proof; proof_bytes=%zu\n", p.len);
    voleith_proof_free(&p);
}

int main(int argc, char **argv) {
    require(argc >= 3, "expected profile and action");
    if (strcmp(argv[1], "256s") == 0) params = &voleith_params_em_256s;
    else if (strcmp(argv[1], "256f") == 0) params = &voleith_params_em_256f;
    else require(0, "unknown verifier profile");
    if (argc == 4 && strcmp(argv[2], "price") == 0) {
        char *end = NULL;
        errno = 0;
        unsigned long bits = strtoul(argv[3], &end, 10);
        require(errno == 0 && argv[3][0] >= '0' && argv[3][0] <= '9' && *end == '\0' &&
                bits <= 1000000000UL, "invalid price input");
        printf("%zu\n", voleith_proof_byte_size(params, bits));
        return 0;
    }
    require(argc == 3, "expected prove, verify, controls or price BITS");
    voleith_circuit_t *c = build();
    const size_t ell = voleith_circuit_witness_count(c) + voleith_circuit_and_gate_count(c);
    const size_t expected = voleith_proof_byte_size(params, ell);
    if (strcmp(argv[2], "prove") == 0) prove(c, expected);
    else if (strcmp(argv[2], "verify") == 0) verify(c, expected, 0);
    else if (strcmp(argv[2], "controls") == 0) verify(c, expected, 1);
    else require(0, "unknown command");
    voleith_circuit_free(c);
    return 0;
}
