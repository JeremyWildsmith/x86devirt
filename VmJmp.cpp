#include "VmJmp.h"

const char* getJumpName(DecodedJump_t jmp) {
    static const char* jmpIndex[] = {
        "jge",
        "jl",
        "jle",
        "jz",
        "jo",
        "jbe",
        "jnz",
        "jno",
        "js",
        "jp",
        "jb",
        "jg",
        "ja",
        "jnp",
        "jns",
        "jnb",
    };

    if(jmp < 0 || jmp > DecodedJump_t::JNB)
        return "???";
    else
        return jmpIndex[jmp];  
}

DecodedJump_t decodeVmJump(const uint8_t jumpEncoded) {
    if(jumpEncoded < 0 || jumpEncoded > DecodedJump_t::JNB)
        return DecodedJump_t::JMP_UNKNOWN;

    return (DecodedJump_t)jumpEncoded;
}