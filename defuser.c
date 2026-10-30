#include "defuser.h"

#include <inttypes.h>
#include <stdio.h>

#define MAX_FIELDS 8

/*
 * 把 values 中的 count 个整数写成一行“空格分隔的无符号十进制整数”，存入 out。
 * 成功返回 0；count 为 0（还没有实现）、snprintf 出错或结果被截断时返回非零。
 */
static int write_answer(char *out, size_t cap, const uint32_t *values, size_t count) {
    size_t used = 0;
    for (size_t i = 0; i < count; ++i) {
        int size = snprintf(out + used, cap - used, "%s%" PRIu32, i ? " " : "", values[i]);
        if (size < 0 || (size_t)size >= cap - used) return 1;
        used += (size_t)size;
    }
    return count == 0;
}

/* ---- 第 1 关 ---------------------------------------------------------- */
/*
 * phase_01 -> p1_compute(challenge)
 *   step2 = (5*hi32 + lo32) ^ 0x2674
 *   step0 = (3*lo32) ^ (((challenge >> 16) & 0xffffffff) + 0x321d)
 *   result = (step0 + 2*step2) ^ 0xa90d
 */
static uint32_t p1_compute(uint64_t challenge) {
    uint32_t lo = (uint32_t)challenge;
    uint32_t hi = (uint32_t)(challenge >> 32);
    uint32_t mid = (uint32_t)(challenge >> 16);
    uint32_t step2 = (uint32_t)(5u * hi + lo) ^ 0x2674u;
    uint32_t step0 = (uint32_t)(3u * lo) ^ (uint32_t)(mid + 0x321du);
    return (uint32_t)(step0 + 2u * step2) ^ 0xa90du;
}

int solve_phase_1(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    values[count++] = p1_compute(challenge);
    return write_answer(out, cap, values, count);
}

/* ---- 第 2 关 ---------------------------------------------------------- */
/*
 * phase_02: 六个整数。首个字段是 (challenge >> 7) & 0x3f，
 * 之后是链式递推：每一步取 (challenge >> (13 + 2*(i-1))) & 0x1f，
 * 加上序号 i，与前一个字段异或，再乘 3。
 */
int solve_phase_2(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    values[count++] = (uint32_t)(challenge >> 7) & 0x3fu;
    for (unsigned i = 1; i <= 5; ++i) {
        uint32_t part = (uint32_t)(challenge >> (13 + 2 * (i - 1))) & 0x1fu;
        values[count] = 3u * ((part + i) ^ values[count - 1]);
        ++count;
    }
    return write_answer(out, cap, values, count);
}

/* ---- 第 3 关 ---------------------------------------------------------- */
/*
 * phase_03: 第一个整数是 challenge & 7，用它做跳转表下标；
 * 第二个整数是 p3_case[c][ (hi32 ^ (challenge >> 3)) & 0xffffffff ]。
 */
static uint32_t p3_dispatch(uint32_t selector, uint32_t x) {
    switch (selector) {
        case 0: return (uint32_t)(4u * x) ^ 0x9043u;
        case 1: return (uint32_t)(5u * x + 0x420e0u);
        case 2: return (uint32_t)((x ^ 0xb90eu) + (x >> 1));
        case 3: return (uint32_t)(4u * x) ^ 0x2d2eu;
        case 4: return (uint32_t)(5u * x + 0x4fbau);
        case 5: return (uint32_t)((x ^ 0xbc1eu) + (x >> 1));
        case 6: return (uint32_t)(5u * x + 0x2323u);
        default: return (uint32_t)(5u * x + 0x95f4u);
    }
}

int solve_phase_3(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    uint32_t selector = (uint32_t)challenge & 7u;
    uint32_t x = (uint32_t)(challenge >> 32) ^ (uint32_t)(challenge >> 3);
    values[count++] = selector;
    values[count++] = p3_dispatch(selector, x);
    return write_answer(out, cap, values, count);
}

/* ---- 第 4 关 ---------------------------------------------------------- */
/*
 * phase_04 -> p4_walk(target = challenge & 0x7f, 0, 0x7f, acc)
 * 在 [lo, hi] 上二分查找 target：命中返回 (mid + 0xbc) ^ acc，
 * 否则递归 5*walk(...) ^ (mid + acc) ^ 0x10（向右）/ 0x1e（向左）。
 */
static uint32_t p4_walk(uint32_t target, uint32_t lo, uint32_t hi, uint32_t acc) {
    uint32_t mid = lo + (uint32_t)((hi - lo) >> 1);
    if (mid == target) return (uint32_t)(mid + 0xbcu) ^ acc;
    if (target > mid) {
        return (uint32_t)(5u * p4_walk(target, mid + 1, hi, acc)) ^ (uint32_t)(mid + acc) ^ 0x10u;
    }
    return (uint32_t)(5u * p4_walk(target, lo, mid - 1, acc)) ^ (uint32_t)(mid + acc) ^ 0x1eu;
}

int solve_phase_4(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    uint32_t acc = (uint32_t)(challenge >> 7) ^ (uint32_t)(challenge >> 32);
    values[count++] = p4_walk((uint32_t)challenge & 0x7fu, 0u, 0x7fu, acc);
    return write_answer(out, cap, values, count);
}

/* ---- 第 5 关 ---------------------------------------------------------- */
/*
 * phase_05: 链表遍历。challenge & 7 选入口节点，遍历 (challenge >> 3) & 3 步。
 * 初值 (challenge >> 6) ^ (challenge >> 32) ^ b0 ^ 0x448f + a0，
 * 每走一步 eax = (eax ^ b) + a；第二个输出是最后访问节点的 a 字段。
 */
struct p5_node {
    int next;      /* -1 表示链尾 */
    uint32_t a;
    uint32_t b;
};

static const struct p5_node p5_nodes[13] = {
    {1, 323u, 16815u},   /* 0: 0x405c40 */
    {2, 1371u, 58466u},  /* 1: 0x405ba0 */
    {3, 1081u, 63290u},  /* 2: 0x405bb0 */
    {4, 2913u, 32279u},  /* 3: 0x405bc0 */
    {-1, 2148u, 61978u}, /* 4: 0x405c50 */
    {6, 628u, 24167u},   /* 5: 0x405c10 */
    {7, 2427u, 11758u},  /* 6: 0x405c20 */
    {8, 2623u, 3706u},   /* 7: 0x405c30 */
    {9, 1804u, 101u},    /* 8: 0x405bf0 */
    {10, 11u, 26086u},   /* 9: 0x405c00 */
    {11, 843u, 18702u},  /* 10: 0x405be0 */
    {0, 1595u, 3876u},   /* 11: 0x405bd0 */
    {-1, 0u, 0u},        /* 12: 未使用 */
};

static const int p5_head[8] = {5, 6, 7, 8, 9, 10, 11, 0};

int solve_phase_5(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    int node = p5_head[challenge & 7u];
    uint32_t a = p5_nodes[node].a;
    uint32_t b = p5_nodes[node].b;
    uint32_t acc = ((uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32)) ^ b ^ 0x448fu;
    uint32_t steps = (uint32_t)(challenge >> 3) & 3u;
    acc = (uint32_t)(acc + a);
    for (uint32_t i = 0; i < steps; ++i) {
        node = p5_nodes[node].next;
        a = p5_nodes[node].a;
        acc = (uint32_t)(acc ^ p5_nodes[node].b);
        acc = (uint32_t)(acc + a);
    }
    values[count++] = acc;
    values[count++] = a;
    return write_answer(out, cap, values, count);
}

/* ---- 第 6 关 ---------------------------------------------------------- */
/*
 * phase_06 -> p6_dispatch(challenge)
 * 先用 challenge & 7 选一个处理例程作用在 (challenge >> 6) ^ (challenge >> 32) 上，
 * 结果异或 0xd92c 后，再用 ((challenge & 0x38) >> 3) 选第二个例程，最后加 0xb3d8。
 */
static uint32_t ror32(uint32_t v, unsigned r) {
    return (v >> r) | (v << (32 - r));
}

static uint32_t rol32(uint32_t v, unsigned r) {
    return (v << r) | (v >> (32 - r));
}

static uint32_t p6_op(uint32_t index, uint32_t x) {
    switch (index) {
        case 0: return (uint32_t)((x ^ 0x9529u) + 2u * x);
        case 1: return (uint32_t)((x + 0x341du) ^ (x >> 3));
        case 2: return ror32(x, 7);
        case 3: return (uint32_t)(((x >> 7) ^ x) + 0x2353u);
        case 4: return rol32(x, 1) ^ 0xff88u;
        default: return (uint32_t)(4u * x + 0x77c3u) ^ (uint32_t)(7u * x);
    }
}

static const unsigned char p6_table[8] = {3, 2, 1, 5, 1, 0, 0, 4};

int solve_phase_6(uint64_t challenge, char *out, size_t cap) {
    uint32_t values[MAX_FIELDS] = {0};
    size_t count = 0;
    uint32_t seed = (uint32_t)(challenge >> 6) ^ (uint32_t)(challenge >> 32);
    uint32_t first = p6_op(p6_table[challenge & 7u], seed) ^ 0xd92cu;
    uint32_t second = p6_op(p6_table[(challenge & 0x38u) >> 3], first);
    values[count++] = (uint32_t)(second + 0xb3d8u);
    return write_answer(out, cap, values, count);
}

/* ---- Honor（第七行）---------------------------------------------------- */
/*
 * secret_gate 先检查 strlen ∈ [36, 163]，再把整行拷到栈上，
 * 要求第 32 个字节起是字面量 "OPEN"，随后用 challenge 与 context 校验三个整数：
 *   f0 = context & 3
 *   m  = ((challenge >> 32) ^ (uint32_t)challenge) ^ ((context >> 32) ^ (uint32_t)context)
 *   f1 = ror32(m, 7) ^ 0x7d8b ^ ((context & 3) * 0x12fd ^ (uint32_t)(context >> 16))
 *   f2 = f1 ^ (((context >> 32) ^ (uint32_t)context) + (context & 3) + 0x6f76
 *              + (((challenge >> 32) ^ (uint32_t)challenge) >> 7))
 * 前 32 个字节不参与校验，这里填一段固定的标识文本。
 */
static const char secret_prefix[33] = "BOMBLAB 2026 HONOR TRANSCRIPT OK";

int solve_secret(uint64_t challenge, uint64_t context, char *out, size_t cap) {
    uint32_t low_ch = (uint32_t)challenge;
    uint32_t low_ctx = (uint32_t)context;
    uint32_t m = ((uint32_t)(challenge >> 32) ^ low_ch) ^ ((uint32_t)(context >> 32) ^ low_ctx);
    uint32_t field0 = low_ctx & 3u;
    uint32_t field1 = ror32(m, 7) ^ 0x7d8bu;
    field1 ^= (uint32_t)(field0 * 0x12fdu) ^ (uint32_t)(context >> 16);
    uint32_t fold = ((uint32_t)(context >> 32) ^ low_ctx) + field0 + 0x6f76u
                    + (((uint32_t)(challenge >> 32) ^ low_ch) >> 7);
    uint32_t field2 = field1 ^ fold;
    int size = snprintf(out, cap, "%sOPEN %" PRIu32 " %" PRIu32 " %" PRIu32,
                        secret_prefix, field0, field1, field2);
    if (size < 0 || (size_t)size >= cap) return 1;
    return 0;
}
