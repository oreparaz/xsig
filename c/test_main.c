#include <stdio.h>
#include <string.h>
#include "xsig.h"
#include "test_vectors.h"

typedef struct {
    const char *name;
    const uint8_t *msg;
    size_t msg_len;
    const uint8_t *xsig;
    size_t xsig_len;
    const uint8_t *xpubkey;
    size_t xpubkey_len;
    int expected;
} test_vector_t;

static int run_test(const test_vector_t *tv) {
    int result = run_machine001(tv->xpubkey, tv->xpubkey_len,
                                tv->xsig, tv->xsig_len,
                                tv->msg, tv->msg_len);
    if (result != tv->expected) {
        printf("FAIL: %s — got %d, expected %d\n", tv->name, result, tv->expected);
        return 1;
    }
    printf("PASS: %s\n", tv->name);
    return 0;
}

int main(void) {
    int failures = 0;

    test_vector_t tests[] = {
        {"single sig verify", tv1_msg, sizeof(tv1_msg), tv1_xsig, sizeof(tv1_xsig), tv1_xpubkey, sizeof(tv1_xpubkey), tv1_expected},
        {"single sig wrong msg", tv2_msg, sizeof(tv2_msg), tv2_xsig, sizeof(tv2_xsig), tv2_xpubkey, sizeof(tv2_xpubkey), tv2_expected},
        {"2-of-3 multisig", tv3_msg, sizeof(tv3_msg), tv3_xsig, sizeof(tv3_xsig), tv3_xpubkey, sizeof(tv3_xpubkey), tv3_expected},
        {"2-of-3 multisig wrong msg", tv4_msg, sizeof(tv4_msg), tv4_xsig, sizeof(tv4_xsig), tv4_xpubkey, sizeof(tv4_xpubkey), tv4_expected},
        {"1-of-1 multisig", tv5_msg, sizeof(tv5_msg), tv5_xsig, sizeof(tv5_xsig), tv5_xpubkey, sizeof(tv5_xpubkey), tv5_expected},
        {"3-of-3 multisig", tv6_msg, sizeof(tv6_msg), tv6_xsig, sizeof(tv6_xsig), tv6_xpubkey, sizeof(tv6_xpubkey), tv6_expected},
        {"duplicate sigs rejected", tv7_msg, sizeof(tv7_msg), tv7_xsig, sizeof(tv7_xsig), tv7_xpubkey, sizeof(tv7_xpubkey), tv7_expected},
        {"empty input", tv8_msg, sizeof(tv8_msg), tv8_xpubkey, tv8_xpubkey_len, tv8_xsig, tv8_xsig_len, tv8_expected},
        {"garbage prefix", tv9_msg, sizeof(tv9_msg), tv9_xsig, sizeof(tv9_xsig), tv9_xpubkey, sizeof(tv9_xpubkey), tv9_expected},
        {"xpubkey eval error", tv10_msg, sizeof(tv10_msg), tv10_xsig, sizeof(tv10_xsig), tv10_xpubkey, sizeof(tv10_xpubkey), tv10_expected},
        {"xsig eval error", tv11_msg, sizeof(tv11_msg), tv11_xsig, sizeof(tv11_xsig), tv11_xpubkey, sizeof(tv11_xpubkey), tv11_expected},
        {"3-of-3 missing signer", tv12_msg, sizeof(tv12_msg), tv12_xsig, sizeof(tv12_xsig), tv12_xpubkey, sizeof(tv12_xpubkey), tv12_expected},
    };

    int n = sizeof(tests) / sizeof(tests[0]);
    for (int i = 0; i < n; i++) {
        failures += run_test(&tests[i]);
    }

    printf("\n%d/%d tests passed\n", n - failures, n);
    return failures > 0 ? 1 : 0;
}
