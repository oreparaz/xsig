#pragma once

#include <stdint.h>
#include <stddef.h>

#define MAX_STACK_SIZE 1024
#define MAX_SIG_DER_LEN 74

typedef struct {
    uint8_t s[MAX_STACK_SIZE];
    int top; // index of next free slot; 0 = empty
} stack_t;

void stack_init(stack_t *st);
int stack_push(stack_t *st, uint8_t val);
int stack_pop(stack_t *st, uint8_t *val);
int stack_is_empty(const stack_t *st);
int stack_push_bytes(stack_t *st, const uint8_t *buf, size_t len);
int stack_pop_bytes(stack_t *st, uint8_t *buf, size_t len);
int stack_pop_pubkey_compressed(stack_t *st, uint8_t *pk_out);
int stack_pop_signature(stack_t *st, uint8_t *sig_out, size_t *sig_len);
