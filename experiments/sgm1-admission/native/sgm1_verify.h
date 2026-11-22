#ifndef SGM1_VERIFY_H
#define SGM1_VERIFY_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#define SGM1_NOEXCEPT noexcept
#else
#define SGM1_NOEXCEPT
#endif
/* Verify a registered proof against an independently supplied genesis pin and 526-byte statement.
 * Returns 1 on acceptance, 0 on rejection. The error buffer is optional. */
int sgm1_verify(const uint8_t *pin, size_t pin_len,
                const uint8_t *statement, size_t statement_len,
                const uint8_t *proof, size_t proof_len,
                char *error, size_t error_len) SGM1_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef SGM1_NOEXCEPT
#endif
