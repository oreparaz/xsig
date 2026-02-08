#include "xsig.h"
#include "eval.h"
#include <string.h>

// "xsig" + MachineType(0) + CodeType
static const uint8_t PREFIX_XPUBKEY[] = {'x','s','i','g', 0x00, 0x00};
static const uint8_t PREFIX_XSIG[]    = {'x','s','i','g', 0x00, 0x01};
#define PREFIX_LEN 6

static int deserialize(const uint8_t *data, size_t data_len,
                       const uint8_t *expected_prefix,
                       const uint8_t **code_out, size_t *code_len_out) {
    if (data_len < PREFIX_LEN) return -1;
    if (memcmp(data, expected_prefix, PREFIX_LEN) != 0) return -1;
    *code_out = data + PREFIX_LEN;
    *code_len_out = data_len - PREFIX_LEN;
    return 0;
}

int run_machine001(const uint8_t *xpubkey, size_t xpubkey_len,
                   const uint8_t *xsig, size_t xsig_len,
                   const uint8_t *msg, size_t msg_len) {
    const uint8_t *code;
    size_t code_len;

    // Phase 1: deserialize and evaluate xsig (no message)
    if (deserialize(xsig, xsig_len, PREFIX_XSIG, &code, &code_len) != 0) {
        return 0;
    }

    eval_t e;
    eval_init(&e);
    if (eval_run(&e, code, code_len) != 0) {
        return 0;
    }

    // Phase 2: transfer stack, deserialize and evaluate xpubkey with message
    eval_t e2;
    eval_init(&e2);
    memcpy(&e2.stack, &e.stack, sizeof(stack_t));

    if (deserialize(xpubkey, xpubkey_len, PREFIX_XPUBKEY, &code, &code_len) != 0) {
        return 0;
    }
    if (eval_with_xmsg(&e2, code, code_len, msg, msg_len) != 0) {
        return 0;
    }

    // Final check: stack must be exactly [1]
    return (e2.stack.top == 1 && e2.stack.s[0] == 1) ? 1 : 0;
}
