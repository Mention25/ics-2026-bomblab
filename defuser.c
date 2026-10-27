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
    /* 分别取低 32 位、第 16～47 位和高 32 位；中间一段与另外两段有重叠。 */
    uint32_t low = (uint32_t)challenge;
    uint32_t middle = (uint32_t)(challenge >> 16);
    uint32_t high = (uint32_t)(challenge >> 32);
    /* p1_compute 先调用 step2(high, low)，再调用 step0(low, middle)。 */
    uint32_t step2 = (3u * high + low) ^ 0x18feu;
    uint32_t step0 = (low + 4u * middle) ^ 0x51fau;
    /* 最后按 step1(step0, step2) 的参数顺序合并结果。 */
    uint32_t value = (3u * step0) ^ (step2 + 0xfbcdu);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[6];
    /* 第一项取 challenge 的第 45～49 位，后五项由前一项递推得到。 */
    values[0] = (uint32_t)(challenge >> 45) & 31u;
    for (unsigned i = 1; i < 6; ++i) {
        /* 从第 14 位开始取连续 5 位，每轮向高位移动 5 位。 */
        uint32_t field = (uint32_t)(challenge >> (9u + 5u * i)) & 31u;
        /* 前一项乘 5 再减下标，与 field 加 13 的结果异或；运算保留低 32 位。 */
        values[i] = (5u * values[i - 1] - i) ^ (field + 13u);
    }
    return write_answer(out, cap, values, 6);
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    /* 最低 3 位决定分支，其余移位和异或操作构造传给分支函数的参数。 */
    uint32_t index = (uint32_t)challenge & 7u;
    uint32_t x = (uint32_t)((challenge >> 3) ^ (challenge >> 32));
    /* 两个输出依次为分支编号和该分支的计算结果。 */
    uint32_t values[2] = {index, 0};
    /* 跳转表依次对应 case_0、case_7、case_5、case_4、case_6、case_2、case_3、case_1，
       因此这里按表下标安排分支，不能直接照函数名的尾号排列。 */
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
    /* 命中中点时停止递归，返回中点加 0x50 后与 salt 异或的结果。 */
    if (target == middle) return (middle + 0x50u) ^ salt;
    if (target < middle) {
        /* 先查左半区间；返回时将子结果乘 3，再异或本层的 middle + salt 和 0x1b。 */
        return (3u * phase4_walk(target, low, middle - 1u, salt))
               ^ (middle + salt) ^ 0x1bu;
    }
    /* 右半区间采用相同的返回计算，但最后异或的常量换成 0x14。 */
    return (3u * phase4_walk(target, middle + 1u, high, salt))
           ^ (middle + salt) ^ 0x14u;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    /* 最低 7 位给出 0～127 内的查找目标，salt 在整条递归路径上保持不变。 */
    uint32_t target = (uint32_t)challenge & 127u;
    uint32_t salt = (uint32_t)((challenge >> 7) ^ (challenge >> 32));
    /* 输出逐层返回并计算得到的结果，而不是查找目标本身。 */
    uint32_t value = phase4_walk(target, 0, 127, salt);
    return write_answer(out, cap, &value, 1);
}

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    /* 原 p5_nodes 的每个节点包含两个 32 位字段和一个 8 字节的后继指针。
       从地址 0x405ba0 起按每 16 字节一个节点编号，下面用编号代替指针。 */
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
        {0x5ba9u, 0x011bu, 12}, /* 12 表示空指针；本题的遍历不会访问这个编号。 */
        {0x4decu, 0x0022u,  1},
        {0x5835u, 0x0334u,  7}
    };
    /* 头指针表把最低 3 位映射为起始节点编号，表下标不直接等于节点编号。 */
    static const unsigned heads[8] = {0, 11, 7, 6, 3, 8, 2, 4};
    unsigned node = heads[challenge & 7u];
    /* 首节点一定会处理，取出的两位表示额外访问次数，所以总次数为 1～4。 */
    unsigned count = (unsigned)((challenge >> 3) & 3u) + 1u;
    uint32_t values[2] = {
        (uint32_t)((challenge >> 6) ^ (challenge >> 32)) ^ 0x33f7u, 0
    };
    for (unsigned i = 0; i < count; ++i) {
        /* 累加当前节点的 value 后乘 5，再与 tag 异或，更新第一个输出。 */
        values[0] = (5u * (values[0] + nodes[node].value)) ^ nodes[node].tag;
        /* 每次覆盖第二个输出，遍历结束时保留的就是最后一个节点的 tag。 */
        values[1] = nodes[node].tag;
        node = nodes[node].next;
    }
    return write_answer(out, cap, values, 2);
}

/* 六个运算都按 32 位无符号数计算，溢出时只保留低 32 位。 */
static uint32_t phase6_op0(uint32_t x) { return (x ^ 0xd231u) + 4u * x; }
static uint32_t phase6_op1(uint32_t x) { return (8u * x + 0x49beu) ^ (7u * x); }
static uint32_t phase6_op2(uint32_t x) { return (x ^ (x >> 5)) + 0x9868u; }
static uint32_t phase6_op3(uint32_t x) { return (x + 0x13dbu) ^ (x >> 1); }
/* 两个方向的移位再按位或，分别还原循环左移 5 位和循环右移 2 位。 */
static uint32_t phase6_op4(uint32_t x) { return ((x << 5) | (x >> 27)) ^ 0x3a06u; }
static uint32_t phase6_op5(uint32_t x) { return (x >> 2) | (x << 30); }

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    /* 按原函数指针表的顺序排列，多个表项可以指向同一个运算函数。 */
    static uint32_t (*const operations[8])(uint32_t) = {
        phase6_op3, phase6_op1, phase6_op0, phase6_op2,
        phase6_op5, phase6_op0, phase6_op4, phase6_op3
    };
    uint32_t x = (uint32_t)((challenge >> 6) ^ (challenge >> 32));
    /* 最低 3 位选择第一次运算，结果先异或 0xd25b，再作为第二次运算的输入。 */
    x = operations[challenge & 7u](x) ^ 0xd25bu;
    /* 第 3～5 位选择第二次运算，返回后加 0xd59b 得到答案。 */
    uint32_t value = operations[(challenge >> 3) & 7u](x) + 0xd59bu;
    return write_answer(out, cap, &value, 1);
}

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    if (out == NULL || cap == 0) return 1;
    /* context 由前六关的口令生成，其最低两位决定第一个整数 mode。 */
    uint32_t mode = (uint32_t)context & 3u;
    /* 分别异或 challenge 和 context 的高低 32 位，再将两次结果合并。 */
    uint32_t folded_challenge = (uint32_t)(challenge ^ (challenge >> 32));
    uint32_t folded_context = (uint32_t)(context ^ (context >> 32));
    uint32_t x = folded_challenge ^ folded_context;
    /* 还原 secret_mix：循环左移 1 位，加 0x2ca1，再异或 0x83b0。 */
    uint32_t mixed = (((x << 1) | (x >> 31)) + 0x2ca1u) ^ 0x83b0u;
    /* 将混合结果与 mode、context 的指定部分异或，得到第二个整数。 */
    uint32_t answer = mixed ^ (mode * 0x2ca1u) ^ (uint32_t)(context >> 16);
    /* 第三个整数由 answer 和括号中的校验值异或得到，加法仍按 32 位计算。 */
    uint32_t check = answer ^ (folded_context + mode + 0x83b0u
                              + (folded_challenge >> 1));
    /* 前 32 个 A 用于占位，OPEN 填在偏移 32 处通过检查，三个整数从偏移 36 开始解析。 */
    int size = snprintf(out, cap, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPEN"
                        "%" PRIu32 " %" PRIu32 " %" PRIu32, mode, answer, check);
    return size < 0 || (size_t)size >= cap;
}
