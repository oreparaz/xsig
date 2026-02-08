#include "der.h"
#include <string.h>

// Parse one DER integer from buf at offset *pos, write 32-byte zero-padded
// big-endian integer to out. Returns 0 on success.
static int parse_der_integer(const uint8_t *buf, size_t buf_len, size_t *pos, uint8_t *out) {
    if (*pos >= buf_len) return -1;
    if (buf[*pos] != 0x02) return -1; // not INTEGER tag
    (*pos)++;

    if (*pos >= buf_len) return -1;
    uint8_t int_len = buf[*pos];
    (*pos)++;

    if (*pos + int_len > buf_len) return -1;

    const uint8_t *int_data = &buf[*pos];
    size_t data_len = int_len;

    // Skip leading zero byte (DER minimal encoding for positive integers)
    if (data_len > 1 && int_data[0] == 0x00) {
        int_data++;
        data_len--;
    }

    if (data_len > 32) return -1; // integer too large for P256

    // Right-align into 32-byte output, zero-pad left
    memset(out, 0, 32);
    memcpy(out + 32 - data_len, int_data, data_len);

    *pos += int_len;
    return 0;
}

int der_to_raw(const uint8_t *der_sig, size_t der_len, uint8_t *raw_out) {
    if (der_len < 6) return -1; // minimum: 30 len 02 01 r 02 01 s = 8 bytes, but at least 6

    size_t pos = 0;

    // SEQUENCE tag
    if (der_sig[pos] != 0x30) return -1;
    pos++;

    // SEQUENCE length
    uint8_t seq_len = der_sig[pos];
    pos++;

    if (pos + seq_len > der_len) return -1;

    // Parse r
    if (parse_der_integer(der_sig, der_len, &pos, raw_out) != 0) {
        return -1;
    }

    // Parse s
    if (parse_der_integer(der_sig, der_len, &pos, raw_out + 32) != 0) {
        return -1;
    }

    return 0;
}
