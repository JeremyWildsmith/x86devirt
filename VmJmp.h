#pragma once
#include <string>

enum DecodedJump_t {
    JGE = 0,
    JL,
    JLE,
    JZ,
    JO,
    JBE,
    JNZ,
    JNO,
    JS,
    JP,
    JB,
    JG,
    JA,
    JNP,
    JNS,
    JNB,
    JMP_UNKNOWN,
};

const char* getJumpName(DecodedJump_t jmp);
DecodedJump_t decodeVmJump(const uint8_t jumpEncoded);