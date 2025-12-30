//go:build windows && amd64

#include "textflag.h"

// Stub de syscall crudo (Windows x64): RCX, RDX, R8, R9, stack...
TEXT ·syscall3(SB),NOSPLIT,$0-48
    // Load arguments
    MOVL sysid+0(FP), AX      // syscall number -> EAX (upper cleared)
    MOVQ a1+8(FP), CX         // arg0
    MOVQ a2+16(FP), DX        // arg1
    MOVQ a3+24(FP), R8        // arg2
    MOVQ CX, R10              // Windows requires R10 = RCX

    SYSCALL

    MOVQ AX, r1+32(FP)        // return value
    MOVL $0, err+40(FP)       // errno unused; keep zero
    RET
