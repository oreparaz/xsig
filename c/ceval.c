// CLI wrapper for differential testing.
// Usage:
//   ceval eval <hex_code> <hex_msg> [hex_device_id]  → prints "ok:<hex_stack>" or "error"
//   ceval m001 <hex_xpubkey> <hex_xsig> <hex_msg> [hex_device_id] → prints "0" or "1"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "eval.h"
#include "xsig.h"

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_cap, size_t *out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len == 0) { *out_len = 0; return 0; }
    if (hex_len % 2 != 0) return -1;
    *out_len = hex_len / 2;
    if (*out_len > out_cap) return -1;
    for (size_t i = 0; i < *out_len; i++) {
        int hi = hex_val(hex[2*i]);
        int lo = hex_val(hex[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int parse_device_id(const char *hex, device_context_t *dctx, uint8_t *dev_buf) {
    size_t dev_len;
    if (hex_to_bytes(hex, dev_buf, 32, &dev_len) != 0 || dev_len != 32) {
        fprintf(stderr, "bad device_id hex (must be exactly 32 bytes)\n");
        return -1;
    }
    dctx->device_id = dev_buf;
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: ceval eval|m001 ...\n");
        return 1;
    }

    // Buffers large enough for any reasonable input
    static uint8_t buf1[65536], buf2[65536], buf3[65536];
    static uint8_t dev_buf[32];
    size_t len1, len2, len3;

    if (strcmp(argv[1], "eval") == 0) {
        if (argc < 4 || argc > 5) {
            fprintf(stderr, "usage: ceval eval <hex_code> <hex_msg> [hex_device_id]\n");
            return 1;
        }
        if (hex_to_bytes(argv[2], buf1, sizeof(buf1), &len1) != 0 ||
            hex_to_bytes(argv[3], buf2, sizeof(buf2), &len2) != 0) {
            fprintf(stderr, "bad hex\n");
            return 1;
        }

        device_context_t dctx;
        const device_context_t *ctx_ptr = NULL;
        if (argc == 5) {
            if (parse_device_id(argv[4], &dctx, dev_buf) != 0) return 1;
            ctx_ptr = &dctx;
        }

        eval_t e;
        eval_init(&e);
        if (ctx_ptr != NULL) e.ctx = ctx_ptr;
        int ret = eval_with_xmsg(&e, buf1, len1, buf2, len2);

        if (ret != 0) {
            printf("error\n");
        } else {
            printf("ok:");
            for (int i = 0; i < e.stack.top; i++)
                printf("%02x", e.stack.s[i]);
            printf("\n");
        }
        return 0;
    }

    if (strcmp(argv[1], "m001") == 0) {
        if (argc < 5 || argc > 6) {
            fprintf(stderr, "usage: ceval m001 <hex_xpubkey> <hex_xsig> <hex_msg> [hex_device_id]\n");
            return 1;
        }
        if (hex_to_bytes(argv[2], buf1, sizeof(buf1), &len1) != 0 ||
            hex_to_bytes(argv[3], buf2, sizeof(buf2), &len2) != 0 ||
            hex_to_bytes(argv[4], buf3, sizeof(buf3), &len3) != 0) {
            fprintf(stderr, "bad hex\n");
            return 1;
        }

        device_context_t dctx;
        const device_context_t *ctx_ptr = NULL;
        if (argc == 6) {
            if (parse_device_id(argv[5], &dctx, dev_buf) != 0) return 1;
            ctx_ptr = &dctx;
        }

        int result = run_machine001_with_context(buf1, len1, buf2, len2, buf3, len3, ctx_ptr);
        printf("%d\n", result);
        return 0;
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 1;
}
