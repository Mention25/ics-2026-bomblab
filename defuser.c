#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    if (out == NULL || cap == 0) return 1;
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t low = (uint32_t)challenge;
    uint32_t middle = (uint32_t)(challenge >> 16);
    uint32_t high = (uint32_t)(challenge >> 32);
    /* p1_compute calls step2(high, low), step0(low, middle), then step1. */
    uint32_t step2 = (3u * high + low) ^ 0x18feu;
    uint32_t step0 = (low + 4u * middle) ^ 0x51fau;
    uint32_t value = (3u * step0) ^ (step2 + 0xfbcdu);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[6];
    values[0] = (uint32_t)(challenge >> 45) & 31u;
    for (unsigned i = 1; i < 6; ++i) {
        uint32_t field = (uint32_t)(challenge >> (9u + 5u * i)) & 31u;
        values[i] = (5u * values[i - 1] - i) ^ (field + 13u);
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t index = (uint32_t)challenge & 7u;
    uint32_t x = (uint32_t)((challenge >> 3) ^ (challenge >> 32));
    uint32_t values[2] = {index, 0};
    /* Jump-table order: case_0, case_7, case_5, case_4,
       case_6, case_2, case_3, case_1. */
    switch (index) {
        case 0: values[1] = (2u * x) ^ 0xf5b1u; break;
        case 1: values[1] = (2u * x) ^ 0xe987u; break;
        case 2: values[1] = 5u * x + 0x3c3bbu; break;
        case 3: values[1] = 5u * x + 0xfbbeu; break;
        case 4: values[1] = (x ^ 0x2ef9u) + (x >> 1); break;
        case 5: values[1] = (x ^ 0xa3e0u) + (x >> 1); break;
        case 6: values[1] = 3u * x + 0xb8a4u; break;
        case 7: values[1] = 5u * x + 0x4fba0u; break;
    }
    return write_answer(out, cap, values, 2);
}

static uint32_t phase4_walk(uint32_t target, uint32_t low,
                            uint32_t high, uint32_t salt) {
    uint32_t middle = low + ((high - low) >> 1);
    if (target == middle) return (middle + 0x50u) ^ salt;
    if (target < middle) {
        return (3u * phase4_walk(target, low, middle - 1u, salt))
               ^ (middle + salt) ^ 0x1bu;
    }
    return (3u * phase4_walk(target, middle + 1u, high, salt))
           ^ (middle + salt) ^ 0x14u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t target = (uint32_t)challenge & 127u;
    uint32_t salt = (uint32_t)((challenge >> 7) ^ (challenge >> 32));
    uint32_t value = phase4_walk(target, 0, 127, salt);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    /* p5_nodes: two 32-bit fields, followed by an 8-byte next pointer.
       Indices below refer to nodes in address order starting at 0x405ba0. */
    static const struct {
        uint32_t value;
        uint32_t tag;
        unsigned next;
    } nodes[] = {
        {0x0414u, 0x0985u, 11},
        {0x8a2cu, 0x085fu,  9},
        {0x4b05u, 0x075du,  4},
        {0x0557u, 0x0633u,  8},
        {0xd2a5u, 0x021eu,  5},
        {0xc8e9u, 0x0462u, 10},
        {0xa905u, 0x0566u,  3},
        {0x491au, 0x0a0du,  6},
        {0x685eu, 0x0b37u,  2},
        {0x5ba9u, 0x011bu, 12}, /* null; never followed by these traversals */
        {0x4decu, 0x0022u,  1},
        {0x5835u, 0x0334u,  7}
    };
    static const unsigned heads[8] = {0, 11, 7, 6, 3, 8, 2, 4};
    unsigned node = heads[challenge & 7u];
    unsigned count = (unsigned)((challenge >> 3) & 3u) + 1u;
    uint32_t values[2] = {
        (uint32_t)((challenge >> 6) ^ (challenge >> 32)) ^ 0x33f7u, 0
    };
    for (unsigned i = 0; i < count; ++i) {
        values[0] = (5u * (values[0] + nodes[node].value)) ^ nodes[node].tag;
        values[1] = nodes[node].tag;
        node = nodes[node].next;
    }
    return write_answer(out, cap, values, 2);
}

/* Each operation uses 32-bit arithmetic, including the two rotations. */
static uint32_t phase6_op0(uint32_t x) { return (x ^ 0xd231u) + 4u * x; }
static uint32_t phase6_op1(uint32_t x) { return (8u * x + 0x49beu) ^ (7u * x); }
static uint32_t phase6_op2(uint32_t x) { return (x ^ (x >> 5)) + 0x9868u; }
static uint32_t phase6_op3(uint32_t x) { return (x + 0x13dbu) ^ (x >> 1); }
static uint32_t phase6_op4(uint32_t x) { return ((x << 5) | (x >> 27)) ^ 0x3a06u; }
static uint32_t phase6_op5(uint32_t x) { return (x >> 2) | (x << 30); }

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    static uint32_t (*const operations[8])(uint32_t) = {
        phase6_op3, phase6_op1, phase6_op0, phase6_op2,
        phase6_op5, phase6_op0, phase6_op4, phase6_op3
    };
    uint32_t x = (uint32_t)((challenge >> 6) ^ (challenge >> 32));
    x = operations[challenge & 7u](x) ^ 0xd25bu;
    uint32_t value = operations[(challenge >> 3) & 7u](x) + 0xd59bu;
    return write_answer(out, cap, &value, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    if (out == NULL || cap == 0) return 1;
    uint32_t mode = (uint32_t)context & 3u;
    uint32_t folded_challenge = (uint32_t)(challenge ^ (challenge >> 32));
    uint32_t folded_context = (uint32_t)(context ^ (context >> 32));
    uint32_t x = folded_challenge ^ folded_context;
    uint32_t mixed = (((x << 1) | (x >> 31)) + 0x2ca1u) ^ 0x83b0u;
    uint32_t answer = mixed ^ (mode * 0x2ca1u) ^ (uint32_t)(context >> 16);
    uint32_t check = answer ^ (folded_context + mode + 0x83b0u
                              + (folded_challenge >> 1));
    /* secret_gate checks OPEN at byte offset 32, then parses at offset 36. */
    int size = snprintf(out, cap, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN"
                        "%" PRIu32 " %" PRIu32 " %" PRIu32, mode, answer, check);
    return size < 0 || (size_t)size >= cap;
}
