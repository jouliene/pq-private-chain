/* Fixed 6-bit diagnostic for an ordered, globally private funded-table lookup. */
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
#include "../../fresh-spend/proof/keccak_circuit.h"

enum { WIDTH = 64, BITS = 512, ROWS = 64, LOW = 4, HIGH = 2, DEPTH = LOW+HIGH,
       HEADER = 4+WIDTH+WIDTH+1, RECORD = 64+8+64+8+64+64, PRIVATE = RECORD+1 };
typedef uint8_t Digest[WIDTH];
typedef wire_id Word[BITS];
typedef struct {
    uint8_t header[HEADER];
    Digest row[ROWS];
    Digest context;
} Table;

static void check(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        exit(EXIT_FAILURE);
    }
}

static void load(Table *t, const char *path) {
    FILE *file = fopen(path, "rb");
    check(file && fread(t->header, 1, HEADER, file) == HEADER, "invalid ledger header");
    unsigned count = t->header[HEADER-1];
    check(!memcmp(t->header, "HLT1", 4) && count && count <= ROWS, "bad ledger format/count");
    check(fread(t->row, WIDTH, count, file) == count && fgetc(file) == EOF &&
          !ferror(file), "bad funded table length");
    fclose(file);
    static const char label[] = "hidden-lookup/component-anf6/full-input/em256f/v1";
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    check(md && EVP_DigestInit_ex(md, EVP_shake256(), NULL) &&
          EVP_DigestUpdate(md, label, sizeof(label)-1) &&
          EVP_DigestUpdate(md, t->header, HEADER) && EVP_DigestUpdate(md, t->row, count*WIDTH) &&
          EVP_DigestFinalXOF(md, t->context, WIDTH), "context digest failed");
    EVP_MD_CTX_free(md);
}

static wire_id monomial(voleith_circuit_t *c, wire_id *set, const wire_id *bits,
                        unsigned mask) {
    unsigned lowbit = mask & -mask;
    wire_id variable = bits[__builtin_ctz(lowbit)];
    return lowbit == mask ? variable : voleith_circuit_add_and(c, set[mask-lowbit], variable);
}

static void lookup(voleith_circuit_t *c, const Table *t, const wire_id *index,
                   const wire_id fixed[2], Word selected) {
    Digest coeff[ROWS];
    memcpy(coeff, t->row, sizeof(coeff));
    for (unsigned step = 1; step < ROWS; step <<= 1)
        for (unsigned i = 0; i < ROWS; ++i)
            if (i & step)
                for (unsigned j = 0; j < WIDTH; ++j) coeff[i][j] ^= coeff[i-step][j];
    wire_id low[1u<<LOW] = {fixed[1]}, high[1u<<HIGH] = {fixed[1]};
    for (unsigned m = 1; m < 1u<<LOW; ++m) low[m] = monomial(c, low, index, m);
    for (unsigned m = 1; m < 1u<<HIGH; ++m) high[m] = monomial(c, high, index+LOW, m);
    for (unsigned bit = 0; bit < BITS; ++bit) {
        wire_id total = fixed[0];
        for (unsigned h = 0; h < 1u<<HIGH; ++h) {
            wire_id part = fixed[0];
            for (unsigned l = 0; l < 1u<<LOW; ++l)
                if ((coeff[(h<<LOW)+l][bit/8] >> (bit%8)) & 1)
                    part = voleith_circuit_add_xor(c, part, low[l]);
            if (h) part = voleith_circuit_add_and(c, part, high[h]);
            total = voleith_circuit_add_xor(c, total, part);
        }
        selected[bit] = total;
    }
    /* Little-endian recurrence: when the new MSBs differ, the public bit wins. */
    unsigned count = t->header[HEADER-1];
    if (count < ROWS) {
        wire_id less = fixed[0];
        for (unsigned j = 0; j < DEPTH; ++j) {
            if ((count >> j) & 1)
                less = voleith_circuit_add_not(c, voleith_circuit_add_and(c, index[j],
                                                  voleith_circuit_add_not(c, less)));
            else
                less = voleith_circuit_add_and(c, voleith_circuit_add_not(c, index[j]), less);
        }
        voleith_circuit_assert_equal(c, less, fixed[1]);
    }
}

static void shake(voleith_circuit_t *c, const wire_id fixed[2], unsigned tag,
                  const wire_id *payload, size_t bytes, Word out) {
    State state;
    size_t len = 2 + bytes, blocks = len/136 + 1;
    for (unsigned lane = 0; lane < 25; ++lane)
        for (unsigned z = 0; z < 64; ++z) state[lane][z] = fixed[0];
    for (size_t block = 0; block < blocks; ++block) {
        for (unsigned byte = 0; byte < 136; ++byte) {
            size_t offset = block*136 + byte;
            uint8_t pad = offset == 0 ? 0xf1 : offset == 1 ? tag : offset == len ? 0x1f : 0;
            if (block == blocks-1 && byte == 135) pad |= 0x80;
            for (unsigned k = 0; k < 8; ++k) {
                wire_id in = offset >= 2 && offset < len ? payload[8*(offset-2)+k] : fixed[(pad>>k)&1];
                unsigned lane = byte/8, z = (byte%8)*8+k;
                state[lane][z] = voleith_circuit_add_xor(c, state[lane][z], in);
            }
        }
        permutation(c, state);
    }
    for (unsigned i = 0; i < BITS; ++i) out[i] = state[i/64][i%64];
}

static voleith_circuit_t *build(const Table *t, int lookup_only) {
    voleith_circuit_t *c = voleith_circuit_new();
    check(c != NULL, "circuit allocation failed");
    wire_id fixed[] = {voleith_circuit_add_const(c, 0), voleith_circuit_add_const(c, 1)};
    wire_id record[RECORD*8], index[DEPTH];
    if (!lookup_only)
        for (unsigned i = 0; i < RECORD*8; ++i) record[i] = voleith_circuit_add_witness(c);
    for (unsigned i = 0; i < DEPTH; ++i) index[i] = voleith_circuit_add_witness(c);
    Word selected, nf;
    lookup(c, t, index, fixed, selected);
    if (lookup_only) {
        memcpy(nf, selected, sizeof(nf));
    } else {
        Word owner, cm, leaf;
        wire_id msg[272*8];
        const wire_id *occ = record + (RECORD-WIDTH)*8;
        shake(c, fixed, 3, record, WIDTH, owner);
        for (unsigned i = 0; i < BITS; ++i)
            msg[i] = fixed[(t->header[4+i/8] >> (i%8)) & 1];
        memcpy(msg+BITS, owner, sizeof(owner));
        /* Private native, asset, quantity and salt follow ASK contiguously. */
        memcpy(msg+2*BITS, record+BITS, (8+64+8+64)*8*sizeof(wire_id));
        shake(c, fixed, 4, msg, 272, cm);
        memcpy(msg, occ, sizeof(Word));
        memcpy(msg+BITS, cm, sizeof(cm));
        shake(c, fixed, 5, msg, 128, leaf);
        for (unsigned bit = 0; bit < BITS; ++bit)
            voleith_circuit_assert_equal(c, selected[bit], leaf[bit]);
        memcpy(msg, record, sizeof(Word));
        memcpy(msg+BITS, occ, sizeof(Word));
        shake(c, fixed, 8, msg, 128, nf);
    }
    for (unsigned i = 0; i < BITS; ++i)
        voleith_circuit_assert_equal(c, nf[i], voleith_circuit_add_instance(c));
    check(voleith_circuit_ok(c) && voleith_circuit_validate(c) == 0, "invalid circuit");
    return c;
}

static void read_exact(uint8_t *dst, size_t n) {
    check(fread(dst, 1, n, stdin) == n, "truncated input");
}
static void end_frame(void) {
    check(fgetc(stdin) == EOF && !ferror(stdin), "unexpected trailing data");
}
static void random32(uint8_t seed[32]) {
    for (size_t i = 0; i < 32;) {
        ssize_t n = getrandom(seed+i, 32-i, 0);
        if (n < 0 && errno == EINTR) continue;
        check(n > 0, "private randomness unavailable");
        i += (size_t)n;
    }
}

static void prove(const Table *t, voleith_circuit_t *c, const voleith_params_t *params,
                  size_t expected) {
    uint8_t w[PRIVATE], coins[32], challenge[5*32+8];
    Digest nf;
    read_exact(w, sizeof(w));
    read_exact(nf, WIDTH);
    end_frame();
    check(w[PRIVATE-1] < ROWS, "noncanonical index");
    size_t nw = (voleith_circuit_wire_count(c)+7)/8;
    uint8_t *vals = malloc(nw);
    check(vals && voleith_circuit_eval(c, w, nf, vals) == 1, "unsatisfied private opening");
    explicit_bzero(vals, nw);
    free(vals);
    random32(coins);
    size_t nb = voleith_commit_blob_size(params, c);
    uint8_t *blob = malloc(nb);
    voleith_prover_commit_t *ctx = NULL;
    check(blob && !voleith_prove_commit(&ctx, params, c, w, nf, coins, sizeof(coins), blob),
          "proof commitment failed");
    explicit_bzero(coins, sizeof(coins));
    voleith_transcript_t tr;
    voleith_transcript_init(&tr, params->lambda, VOLEITH_FS_H2_1);
    voleith_transcript_absorb(&tr, t->context, WIDTH);
    voleith_transcript_absorb(&tr, nf, WIDTH);
    voleith_transcript_absorb(&tr, blob, nb);
    voleith_transcript_squeeze(&tr, challenge, sizeof(challenge));
    voleith_transcript_clear(&tr);
    free(blob);
    voleith_proof_t p = {0};
    check(!voleith_prove_respond(&p, ctx, c, w, nf, challenge), "proof response failed");
    explicit_bzero(w, sizeof(w));
    voleith_prover_commit_free(ctx);
    check(p.len == expected && fwrite(nf, 1, WIDTH, stdout) == WIDTH &&
          fwrite(p.data, 1, p.len, stdout) == p.len && !fflush(stdout), "proof write failed");
    voleith_proof_free(&p);
}

int main(int argc, char **argv) {
    check(argc == 3, "expected prove/verify/geometry/check-table and authoritative table path");
    Table table = {0};
    load(&table, argv[2]);
    int table_check = !strcmp(argv[1], "check-table");
    voleith_circuit_t *c = build(&table, table_check);
    const voleith_params_t *params = &voleith_params_em_256f;
    size_t ands = voleith_circuit_and_gate_count(c), bits = voleith_circuit_witness_count(c);
    size_t size = voleith_proof_byte_size(params, ands+bits);
    if (table_check) {
        uint8_t *vals = malloc((voleith_circuit_wire_count(c)+7)/8);
        check(vals != NULL, "check allocation failed");
        for (uint8_t i = 0; i < ROWS; ++i) {
            int occupied = i < table.header[HEADER-1];
            check(voleith_circuit_eval(c, &i, table.row[i], vals) == occupied,
                  "lookup disagrees with independent ordered table");
            Digest wrong;
            memcpy(wrong, table.row[i], WIDTH);
            wrong[0] ^= 1;
            check(voleith_circuit_eval(c, &i, wrong, vals) == 0, "incorrect table row matched");
        }
        free(vals);
        printf("checked all %d positions and a changed row at each\n", ROWS);
    } else if (!strcmp(argv[1], "geometry")) {
        printf("{\"ands\":%zu,\"witness_bits\":%zu,\"wires\":%zu,\"proof_bytes\":%zu}\n",
               ands, bits, voleith_circuit_wire_count(c), size);
    } else if (!strcmp(argv[1], "prove")) {
        prove(&table, c, params, size);
    } else if (!strcmp(argv[1], "verify")) {
        Digest nf;
        voleith_proof_t p = {.len = size, .data = malloc(size)};
        check(p.data != NULL, "proof allocation failed");
        read_exact(nf, WIDTH);
        read_exact(p.data, p.len);
        end_frame();
        check(!voleith_verify_v2(&p, params, c, nf, WIDTH, table.context, WIDTH),
              "public proof rejected");
        voleith_proof_free(&p);
        puts("public input opening accepted");
    } else check(0, "unknown action");
    voleith_circuit_free(c);
    return 0;
}
