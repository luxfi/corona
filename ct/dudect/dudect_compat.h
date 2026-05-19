/*
 * Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
 * See the file LICENSE for licensing terms.
 *
 * dudect_compat.h -- minimal x86-intrinsic compatibility shim for
 * AArch64 hosts.
 *
 * Mirrors ~/work/lux/pulsar/ct/dudect/dudect_compat.h byte-equal at
 * the AArch64 path (the upstream dudect.h hardcodes x86 intrinsics for
 * cycle counting; this shim supplies AArch64 equivalents).
 */

#ifndef DUDECT_COMPAT_H
#define DUDECT_COMPAT_H

#if defined(__aarch64__)

#include <stdint.h>

#define _EMMINTRIN_H_INCLUDED
#define __EMMINTRIN_H
#define _IMMINTRIN_H_INCLUDED
#define _X86INTRIN_H_INCLUDED
#define __X86INTRIN_H

static inline void _mm_mfence(void) {
    __asm__ __volatile__("dsb sy" ::: "memory");
}

#if defined(__APPLE__)

#include <mach/mach_time.h>

static inline uint64_t __rdtsc(void) {
    return mach_absolute_time();
}

#else  /* Linux / *BSD on AArch64 */

static inline uint64_t __rdtsc(void) {
    uint64_t v;
    __asm__ __volatile__("isb; mrs %0, cntvct_el0" : "=r" (v));
    return v;
}

#endif /* __APPLE__ */

#endif /* __aarch64__ */

#endif /* DUDECT_COMPAT_H */
