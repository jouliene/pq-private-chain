/* A single binary VOLE proof of two linked FS01 parents, with a verifier-selected root. */
#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include "proof.h"
#include "fiat_shamir.h"
#include "../../fresh-spend/proof/keccak_circuit.h"

enum { WIDTH = 512, PRIVATE_BITS = 4 * WIDTH + 1, ANDS = 2 * 38400 + WIDTH };
typedef wire_id word[WIDTH];
static const unsigned char domain[] = "funded-membership/fs01/linked-parents/vole-256s/v1";

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void exact(FILE *stream, unsigned char *buffer, size_t bytes) {
    require(stream && fread(buffer, 1, bytes, stream) == bytes &&
            fgetc(stream) == EOF && !ferror(stream), "invalid input length");
}

static void parent_hash(voleith_circuit_t *c, unsigned int level,
                        const word left, const word right, word digest) {
    /* FIPS 202 SHAKE256 absorbs 131 bytes, then pad10*1 at a 136-byte rate. */
    unsigned char constants[200] = { [0] = 0xf1, [1] = 7, [131] = 0x1f, [135] = 0x80 };
    constants[2] = (unsigned char)level;
    wire_id zero_one[] = {voleith_circuit_add_const(c, 0), voleith_circuit_add_const(c, 1)};
    State state;
    for (unsigned int i = 0; i < 1600; ++i) {
        wire_id w = zero_one[(constants[i / 8] >> (i % 8)) & 1];
        if (i >= 24 && i < 24 + WIDTH) w = left[i - 24];
        else if (i >= 24 + WIDTH && i < 24 + 2 * WIDTH) w = right[i - 24 - WIDTH];
        state[i/64][i%64] = w;
    }
    permutation(c, state);
    for (unsigned int i = 0; i < WIDTH; ++i) digest[i] = state[i/64][i%64];
}

static voleith_circuit_t *linked(void) {
    voleith_circuit_t *c = voleith_circuit_new();
    require(c != NULL, "circuit allocation failed");
    word inputs[4]; /* First pair, outer sibling and claimed intermediate. */
    for (size_t i = 0; i < 4; ++i)
        for (size_t j = 0; j < WIDTH; ++j) inputs[i][j] = voleith_circuit_add_witness(c);
    wire_id select = voleith_circuit_add_witness(c);
    word first, left, right, result;
    parent_hash(c, 0, inputs[0], inputs[1], first);
    for (size_t j = 0; j < WIDTH; ++j) {
        voleith_circuit_assert_equal(c, first[j], inputs[3][j]);
        wire_id difference = voleith_circuit_add_xor(c, inputs[3][j], inputs[2][j]);
        wire_id toggle = voleith_circuit_add_and(c, select, difference);
        left[j] = voleith_circuit_add_xor(c, inputs[3][j], toggle);
        right[j] = voleith_circuit_add_xor(c, inputs[2][j], toggle);
    }
    parent_hash(c, 1, left, right, result);
    for (size_t j = 0; j < WIDTH; ++j)
        voleith_circuit_assert_equal(c, result[j], voleith_circuit_add_instance(c));
    require(voleith_circuit_ok(c) && voleith_circuit_validate(c) == 0 &&
            voleith_circuit_witness_count(c) == PRIVATE_BITS &&
            voleith_circuit_and_gate_count(c) == ANDS, "invalid registered circuit");
    return c;
}

static void prove(voleith_circuit_t *c, const unsigned char root[64], size_t size, int negative) {
    const voleith_params_t *p = &voleith_params_em_256s;
    unsigned char w[(PRIVATE_BITS + 7) / 8], coins[32], challenge[168];
    exact(stdin, w, sizeof(w));
    require(w[sizeof(w)-1] <= 1 && RAND_priv_bytes(coins, sizeof(coins)) == 1, "witness/coins");
    size_t len = voleith_commit_blob_size(p, c);
    unsigned char *blob = malloc(len);
    voleith_prover_commit_t *ctx = NULL;
    require(blob && voleith_prove_commit(&ctx, p, c, w, root, coins, sizeof(coins), blob) == 0,
            "commit failed");
    explicit_bzero(coins, sizeof(coins));
    voleith_transcript_t t;
    voleith_transcript_init(&t, p->lambda, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&t, domain, sizeof(domain)-1);
    voleith_transcript_absorb(&t, root, 64);
    voleith_transcript_absorb(&t, blob, len);
    voleith_transcript_squeeze(&t, challenge, sizeof(challenge));
    voleith_transcript_clear(&t);
    free(blob);
    voleith_proof_t proof = {0};
    int rc = voleith_prove_respond(&proof, ctx, c, w, root, challenge);
    explicit_bzero(w, sizeof(w));
    voleith_prover_commit_free(ctx);
    if (negative) require(rc != 0 && proof.len == 0, "inconsistent witness produced a proof");
    else require(rc == 0 && proof.len == size &&
                 fwrite(proof.data, 1, size, stdout) == size && fflush(stdout) == 0, "prove failed");
    voleith_proof_free(&proof);
}

int main(int argc, char **argv) {
    require(argc == 3, "expected action and verifier root path");
    FILE *f = fopen(argv[2], "rb");
    unsigned char root[64];
    exact(f, root, sizeof(root));
    require(fclose(f) == 0, "close root");
    voleith_circuit_t *c = linked();
    const voleith_params_t *p = &voleith_params_em_256s;
    size_t size = voleith_proof_byte_size(p, PRIVATE_BITS + ANDS);
    if (strcmp(argv[1], "prove") == 0 || strcmp(argv[1], "inconsistent") == 0) {
        prove(c, root, size, strcmp(argv[1], "inconsistent") == 0);
    } else {
        int negative = strcmp(argv[1], "reject") == 0;
        require(negative || strcmp(argv[1], "verify") == 0, "unknown action");
        voleith_proof_t proof = {.len = size, .data = malloc(size)};
        require(proof.data != NULL, "proof allocation");
        exact(stdin, proof.data, proof.len);
        int rc = voleith_verify_v2(&proof, p, c, root, sizeof(root), domain, sizeof(domain)-1);
        require(negative ? rc != 0 : rc == 0, "unexpected verification result");
        voleith_proof_free(&proof);
    }
    voleith_circuit_free(c);
    return 0;
}
