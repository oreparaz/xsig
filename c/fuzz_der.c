#include <stdint.h>
#include <stddef.h>
#include "der.h"

// Fuzz the DER-to-raw signature converter.
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t raw[64];
    der_to_raw(data, size, raw);
    return 0;
}
