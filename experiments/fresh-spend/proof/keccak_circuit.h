#ifndef FS01_KECCAK_CIRCUIT_H
#define FS01_KECCAK_CIRCUIT_H

#include <stdint.h>
#include "circuit.h"

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

#endif
