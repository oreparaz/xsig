#include "stack.h"

void stack_init(xstack_t *st) {
    st->top = 0;
}

int stack_push(xstack_t *st, uint8_t val) {
    if (st->top >= MAX_STACK_SIZE) {
        return -1; // stack overflow
    }
    st->s[st->top++] = val;
    return 0;
}

int stack_pop(xstack_t *st, uint8_t *val) {
    if (st->top <= 0) {
        return -1; // stack underflow
    }
    *val = st->s[--st->top];
    return 0;
}

int stack_is_empty(const xstack_t *st) {
    return st->top == 0;
}

int stack_push_bytes(xstack_t *st, const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (stack_push(st, buf[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

int stack_pop_bytes(xstack_t *st, uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (stack_pop(st, &buf[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

int stack_pop_pubkey_compressed(xstack_t *st, uint8_t *pk_out) {
    // Pop 33 bytes (LIFO order) matching Go's PopPublicKeyCompressed
    if (stack_pop_bytes(st, pk_out, 33) != 0) {
        return -1;
    }
    if (pk_out[0] != 0x02 && pk_out[0] != 0x03) {
        return -2; // unknown public key format
    }
    return 0;
}

int stack_pop_signature(xstack_t *st, uint8_t *sig_out, size_t *sig_len) {
    // Parse DER: 0x30 || L1 || [L1 bytes]
    uint8_t marker;
    if (stack_pop(st, &marker) != 0) {
        return -1; // underflow
    }
    if (marker != 0x30) {
        return -2; // not valid DER encoding
    }
    sig_out[0] = marker;

    uint8_t sig_body_len;
    if (stack_pop(st, &sig_body_len) != 0) {
        return -1; // underflow
    }
    if (2 + (size_t)sig_body_len > MAX_SIG_DER_LEN) {
        return -3; // DER signature too long
    }
    sig_out[1] = sig_body_len;

    for (int i = 0; i < (int)sig_body_len; i++) {
        if (stack_pop(st, &sig_out[2 + i]) != 0) {
            return -1; // underflow
        }
    }

    *sig_len = 2 + (size_t)sig_body_len;
    return 0;
}
