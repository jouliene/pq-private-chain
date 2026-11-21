/* Measure the upstream LowMC signature component with disposable keys. */
#define _POSIX_C_SOURCE 200809L
#include "picnic.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { PROBE_TRIALS = 3, PUBLIC_KEY_BYTES = 65, SIGNATURE_BYTES = 209506 };

static void require(int condition, const char *reason)
{
    if (!condition) {
        fprintf(stderr, "%s\n", reason);
        exit(1);
    }
}

static double process_cpu_ms(void)
{
    struct timespec t;
    require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t) == 0, "clock_gettime failed");
    return 1000.0 * (double)t.tv_sec + (double)t.tv_nsec / 1e6;
}

static void measure_sign(FILE *wire, uint8_t *signature)
{
    picnic_privatekey_t sk;
    picnic_publickey_t pk;
    uint8_t key_bytes[PUBLIC_KEY_BYTES];

    require(picnic_keygen(Picnic_L5_UR, &pk, &sk) == 0, "keygen failed");
    require(picnic_write_public_key(&pk, key_bytes, sizeof(key_bytes)) == PUBLIC_KEY_BYTES,
            "unexpected public key length");
    require(fwrite(key_bytes, 1, sizeof(key_bytes), wire) == sizeof(key_bytes),
            "public key write failed");
    for (uint8_t trial = 0; trial < PROBE_TRIALS; ++trial) {
        uint8_t message[] = { 'L', '5', '-', 'U', 'R', trial };
        size_t length = SIGNATURE_BYTES;
        double start = process_cpu_ms();
        int result = picnic_sign(&sk, message, sizeof(message), signature, &length);
        double elapsed = process_cpu_ms() - start;
        require(result == 0 && length == SIGNATURE_BYTES, "unexpected sign result");
        require(fwrite(signature, 1, length, wire) == length, "signature write failed");
        printf("sign_cpu_ms %.3f\n", elapsed);
    }
    printf("signature_bytes %d\n", SIGNATURE_BYTES);
}

static void measure_verify(FILE *wire, uint8_t *signature)
{
    picnic_publickey_t pk;
    uint8_t key_bytes[PUBLIC_KEY_BYTES];

    require(fread(key_bytes, 1, sizeof(key_bytes), wire) == sizeof(key_bytes),
            "public key read failed");
    require(picnic_read_public_key(&pk, key_bytes, sizeof(key_bytes)) == 0
                && pk.params == Picnic_L5_UR,
            "unexpected public key format");
    for (uint8_t trial = 0; trial < PROBE_TRIALS; ++trial) {
        uint8_t message[] = { 'L', '5', '-', 'U', 'R', trial };
        require(fread(signature, 1, SIGNATURE_BYTES, wire) == SIGNATURE_BYTES,
                "signature read failed");
        double start = process_cpu_ms();
        int result = picnic_verify(&pk, message, sizeof(message), signature, SIGNATURE_BYTES);
        double elapsed = process_cpu_ms() - start;
        require(result == 0, "public verification failed");
        printf("verify_cpu_ms %.3f\n", elapsed);

        if (trial == PROBE_TRIALS - 1) {
            message[0] ^= 1;
            require(picnic_verify(&pk, message, sizeof(message), signature, SIGNATURE_BYTES) != 0,
                    "changed message accepted");
            message[0] ^= 1;
            signature[110 + 32] ^= 1;
            require(picnic_verify(&pk, message, sizeof(message), signature, SIGNATURE_BYTES) != 0,
                    "changed commitment accepted");
        }
    }
    require(fgetc(wire) == EOF && !ferror(wire), "unexpected public probe bytes");
    puts("changed_message rejected");
    puts("changed_commitment rejected");
}

int main(int argc, char **argv)
{
    require(argc == 3, "usage: picnic_ur_probe sign|verify PUBLIC_FILE");
    int sign = strcmp(argv[1], "sign") == 0;
    require(sign || strcmp(argv[1], "verify") == 0, "unknown mode");
    require(picnic_signature_size(Picnic_L5_UR) == SIGNATURE_BYTES,
            "the library does not match the size pin");
    FILE *wire = fopen(argv[2], sign ? "wbx" : "rb");
    uint8_t *signature = malloc(SIGNATURE_BYTES);
    require(wire != NULL && signature != NULL, "public file or signature allocation failed");
    if (sign) {
        measure_sign(wire, signature);
    } else {
        measure_verify(wire, signature);
    }
    require(fclose(wire) == 0, "public file close failed");
    free(signature);
    return 0;
}
