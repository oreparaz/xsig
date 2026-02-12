#include <stdio.h>
#include <string.h>
#include "eval.h"
#include "xsig.h"
#include "test_vectors.h"

static int run_eval_test(const eval_tv_t *tv) {
    eval_t e;
    eval_init(&e);

    if (tv->device_id_len > 0) {
        static device_context_t dctx;
        dctx.device_id = tv->device_id;
        dctx.device_id_len = tv->device_id_len;
        e.ctx = &dctx;
    }

    int ret = eval_with_xmsg(&e, tv->code, tv->code_len, tv->msg, tv->msg_len);

    if (tv->expect_error) {
        if (ret == 0) {
            printf("FAIL: %s — expected error, got success\n", tv->name);
            return 1;
        }
        return 0;
    }

    if (ret != 0) {
        printf("FAIL: %s — expected success, got error\n", tv->name);
        return 1;
    }

    if ((size_t)e.stack.top != tv->expect_stack_len) {
        printf("FAIL: %s — stack len %d, expected %zu\n",
               tv->name, e.stack.top, tv->expect_stack_len);
        return 1;
    }

    if (tv->expect_stack_len > 0 &&
        memcmp(e.stack.s, tv->expect_stack, tv->expect_stack_len) != 0) {
        printf("FAIL: %s — stack content mismatch\n  got:    ", tv->name);
        for (size_t i = 0; i < (size_t)e.stack.top; i++)
            printf("%02x", e.stack.s[i]);
        printf("\n  expect: ");
        for (size_t i = 0; i < tv->expect_stack_len; i++)
            printf("%02x", tv->expect_stack[i]);
        printf("\n");
        return 1;
    }

    return 0;
}

static int run_m001_test(const m001_tv_t *tv) {
    int result = run_machine001(tv->xpubkey, tv->xpubkey_len,
                                tv->xsig, tv->xsig_len,
                                tv->msg, tv->msg_len);
    if (result != tv->expected) {
        printf("FAIL: %s — got %d, expected %d\n", tv->name, result, tv->expected);
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    int eval_failures = 0;
    int m001_failures = 0;

    printf("=== Eval Tests (%d) ===\n", NUM_EVAL_TESTS);
    for (int i = 0; i < NUM_EVAL_TESTS; i++) {
        eval_failures += run_eval_test(&eval_tests[i]);
    }

    printf("=== Machine001 Tests (%d) ===\n", NUM_M001_TESTS);
    for (int i = 0; i < NUM_M001_TESTS; i++) {
        m001_failures += run_m001_test(&m001_tests[i]);
    }

    failures = eval_failures + m001_failures;
    int total = NUM_EVAL_TESTS + NUM_M001_TESTS;

    printf("\nEval:       %d/%d passed\n", NUM_EVAL_TESTS - eval_failures, NUM_EVAL_TESTS);
    printf("Machine001: %d/%d passed\n", NUM_M001_TESTS - m001_failures, NUM_M001_TESTS);
    printf("Total:      %d/%d passed\n", total - failures, total);

    return failures > 0 ? 1 : 0;
}
