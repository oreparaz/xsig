#include "eval.h"
#include "der.h"
#include "p256/p256.h"
#include <string.h>

void eval_init(eval_t *e) {
    stack_init(&e->stack);
    e->ctx = NULL;
}

static int do_sigverify(eval_t *e, const uint8_t *xmsg, size_t xmsg_len) {
    uint8_t pk[33];
    if (stack_pop_pubkey_compressed(&e->stack, pk) != 0) {
        return -1;
    }

    uint8_t der_sig[MAX_SIG_DER_LEN];
    size_t der_len;
    if (stack_pop_signature(&e->stack, der_sig, &der_len) != 0) {
        return -1;
    }

    uint8_t raw_sig[64];
    if (der_to_raw(der_sig, der_len, raw_sig) != 0) {
        return -1;
    }

    p256_ret_t ret = p256_verify((uint8_t *)xmsg, xmsg_len, raw_sig, pk);
    return stack_push(&e->stack, ret == P256_SUCCESS ? 1 : 0);
}

static int do_multisigverify(eval_t *e, const uint8_t *xmsg, size_t xmsg_len) {
    uint8_t n_public_keys, n_min_valid;

    if (stack_pop(&e->stack, &n_public_keys) != 0) return -1;
    if (stack_pop(&e->stack, &n_min_valid) != 0) return -1;

    if (n_public_keys == 0) return -1;
    if (n_min_valid == 0) return -1;
    if (n_min_valid > n_public_keys) return -1;

    // Pop public keys (max 255)
    uint8_t pks[255][33];
    for (int i = 0; i < (int)n_public_keys; i++) {
        if (stack_pop_pubkey_compressed(&e->stack, pks[i]) != 0) {
            return -1;
        }
    }

    // Pop signatures
    uint8_t sigs[255][MAX_SIG_DER_LEN];
    size_t sig_lens[255];
    for (int i = 0; i < (int)n_min_valid; i++) {
        if (stack_pop_signature(&e->stack, sigs[i], &sig_lens[i]) != 0) {
            return -1;
        }
    }

    // Verify: for each public key, try each signature.
    // Matches Go's outer=keys, inner=sigs loop.
    int count_valid = 0;
    for (int i = 0; i < (int)n_public_keys; i++) {
        for (int j = 0; j < (int)n_min_valid; j++) {
            uint8_t raw_sig[64];
            if (der_to_raw(sigs[j], sig_lens[j], raw_sig) != 0) {
                continue;
            }
            if (p256_verify((uint8_t *)xmsg, xmsg_len, raw_sig, pks[i]) == P256_SUCCESS) {
                count_valid++;
                break; // next key (continue OUTER in Go)
            }
        }
    }

    return stack_push(&e->stack, count_valid >= (int)n_min_valid ? 1 : 0);
}

int eval_with_xmsg(eval_t *e, const uint8_t *code, size_t code_len,
                   const uint8_t *xmsg, size_t xmsg_len) {
    size_t pc = 0;

    while (pc < code_len) {
        uint8_t opcode = code[pc];

        switch (opcode) {
        case OP_ADD: {
            uint8_t a, b;
            if (stack_pop(&e->stack, &a) != 0) return -1;
            if (stack_pop(&e->stack, &b) != 0) return -1;
            if (stack_push(&e->stack, (uint8_t)(a + b)) != 0) return -1;
            pc++;
            break;
        }
        case OP_MUL: {
            uint8_t a, b;
            if (stack_pop(&e->stack, &a) != 0) return -1;
            if (stack_pop(&e->stack, &b) != 0) return -1;
            if (stack_push(&e->stack, (uint8_t)(a * b)) != 0) return -1;
            pc++;
            break;
        }
        case OP_AND: {
            uint8_t a, b;
            if (stack_pop(&e->stack, &a) != 0) return -1;
            if (stack_pop(&e->stack, &b) != 0) return -1;
            if (stack_push(&e->stack, a & b) != 0) return -1;
            pc++;
            break;
        }
        case OP_OR: {
            uint8_t a, b;
            if (stack_pop(&e->stack, &a) != 0) return -1;
            if (stack_pop(&e->stack, &b) != 0) return -1;
            if (stack_push(&e->stack, a | b) != 0) return -1;
            pc++;
            break;
        }
        case OP_NOT: {
            uint8_t a;
            if (stack_pop(&e->stack, &a) != 0) return -1;
            if (stack_push(&e->stack, (uint8_t)~a) != 0) return -1;
            pc++;
            break;
        }
        case OP_PUSH: {
            if (pc + 1 >= code_len) return -1; // missing length operand
            uint8_t how_many = code[pc + 1];
            if (pc + 2 + how_many > code_len) return -1; // operand extends past end
            for (int i = 0; i < (int)how_many; i++) {
                if (stack_push(&e->stack, code[pc + 2 + i]) != 0) return -1;
            }
            pc = pc + 2 + how_many;
            break;
        }
        case OP_SIGVERIFY: {
            if (do_sigverify(e, xmsg, xmsg_len) != 0) return -1;
            pc++;
            break;
        }
        case OP_MULTISIGVERIFY: {
            if (do_multisigverify(e, xmsg, xmsg_len) != 0) return -1;
            pc++;
            break;
        }
        case OP_EQUAL32: {
            uint8_t a[32], b[32];
            if (stack_pop_bytes(&e->stack, a, 32) != 0) return -1;
            if (stack_pop_bytes(&e->stack, b, 32) != 0) return -1;
            if (stack_push(&e->stack, (uint8_t)(memcmp(a, b, 32) == 0 ? 1 : 0)) != 0) return -1;
            pc++;
            break;
        }
        case OP_DEVICEID: {
            if (e->ctx == NULL || e->ctx->device_id == NULL || e->ctx->device_id_len != 32) {
                return -1;
            }
            for (int i = 31; i >= 0; i--) {
                if (stack_push(&e->stack, e->ctx->device_id[i]) != 0) return -1;
            }
            pc++;
            break;
        }
        default:
            return -1; // unknown opcode
        }
    }

    return 0;
}

int eval_run(eval_t *e, const uint8_t *code, size_t code_len) {
    return eval_with_xmsg(e, code, code_len, (const uint8_t *)"", 0);
}
