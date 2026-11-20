/* Verify and attribute one public Picnic3 KAT signature using the pinned reference library. */
#include "picnic.h"
#include "picnic3_impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_param_set(picnic_params_t variant, paramset_t* params);

/* The driver passes only public KAT material. Bounds cover all three reference profiles. */
int main(void) {
    uint8_t pkbuf[100], message[33], sigbuf[70000], again[70000];
    size_t pk_n, sig_n;
    if (scanf("%zu %zu", &pk_n, &sig_n) != 2 || getchar() != '\n' ||
        pk_n > sizeof(pkbuf) || sig_n > sizeof(sigbuf) ||
        fread(pkbuf, 1, pk_n, stdin) != pk_n ||
        fread(message, 1, sizeof(message), stdin) != sizeof(message) ||
        fread(sigbuf, 1, sig_n, stdin) != sig_n || getchar() != EOF) return 1;
    picnic_publickey_t pk;
    paramset_t p;
    signature2_t sig;
    if (picnic_read_public_key(&pk, pkbuf, pk_n) != 0 ||
        (pk.params != Picnic3_L1 && pk.params != Picnic3_L3 && pk.params != Picnic3_L5) ||
        get_param_set(pk.params, &p) != 0 ||
        picnic_verify(&pk, message, sizeof(message), sigbuf, sig_n) != 0) return 2;
    allocateSignature2(&sig, &p);
    if (deserializeSignature2(&sig, sigbuf, sig_n, &p) != EXIT_SUCCESS ||
        serializeSignature2(&sig, again, sizeof(again), &p) != (int)sig_n ||
        memcmp(again, sigbuf, sig_n)) return 3;
    size_t present_aux = 0, seed_info = 0;
    for (size_t i = 0; i < p.numOpenedRounds; i++) {
        size_t t = sig.challengeC[i];
        present_aux += sig.challengeP[i] != p.numMPCParties-1;
        seed_info += sig.proofs[t].seedInfoLen;
    }
    size_t opened = p.numOpenedRounds;
    size_t gate_bits = 3*p.numRounds*p.numSboxes;
    size_t messages = opened*p.andSizeBytes, corrections = present_aux*p.andSizeBytes;
    size_t masked_inputs = opened*p.stateSizeBytes, commitments = opened*p.digestSizeBytes;
    size_t header = p.digestSizeBytes+p.saltSizeBytes;
    size_t accounted = header+sig.iSeedInfoLen+sig.cvInfoLen+seed_info+masked_inputs+messages+corrections+commitments;
    if (accounted != sig_n || seed_info != opened*4*p.seedSizeBytes) return 4;
    printf("{\"executions\":%u,\"opened\":%zu,\"parties\":%u,\"ANDs\":%zu,"
           "\"aux_openings\":%zu,\"signature_B\":%zu,\"header_B\":%zu,"
           "\"initial_seed_cover_B\":%zu,\"view_merkle_cover_B\":%zu,\"party_seeds_B\":%zu,"
           "\"aux_B\":%zu,\"masked_inputs_B\":%zu,\"online_msgs_B\":%zu,\"party_commitments_B\":%zu}\n",
           (unsigned)p.numMPCRounds, opened, (unsigned)p.numMPCParties, gate_bits, present_aux, sig_n, header,
           sig.iSeedInfoLen, sig.cvInfoLen, seed_info, corrections, masked_inputs, messages, commitments);
    freeSignature2(&sig, &p);
    return 0;
}
