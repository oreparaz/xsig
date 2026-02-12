#pragma once

#include <stdint.h>
#include <stddef.h>
#include "stack.h"

#define OP_ADD            1
#define OP_MUL            2
#define OP_PUSH           3
#define OP_SIGVERIFY      4
#define OP_MULTISIGVERIFY 5
#define OP_AND            6
#define OP_OR             7
#define OP_NOT            8
#define OP_EQUAL32        9
#define OP_DEVICEID       10

typedef struct {
    const uint8_t *device_id; // exactly 32 bytes, or NULL if not set
} device_context_t;

typedef struct {
    xstack_t stack;
    const device_context_t *ctx;
} eval_t;

void eval_init(eval_t *e);

// Evaluate bytecode with message (for signature verification).
// Returns 0 on success, nonzero on error.
int eval_with_xmsg(eval_t *e, const uint8_t *code, size_t code_len,
                   const uint8_t *xmsg, size_t xmsg_len);

// Evaluate bytecode without message (xmsg = empty).
int eval_run(eval_t *e, const uint8_t *code, size_t code_len);
