//go:build windows && amd64

#include "textflag.h"

// Lectura del PEB vía GS:[0x60]; evita llamar APIs.
TEXT ·getPEB(SB),NOSPLIT,$0-8
    MOVQ 0x60(GS), AX
    MOVQ AX, ret+0(FP)
    RET
