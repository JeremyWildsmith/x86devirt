#pragma once

#include <string>

enum DecodedRegister_t {
    EFLAGS = 0,
    EDI,
    ESI,
    EBP,
    ESP,
    EBX,
    EDX,
    ECX,
    EAX,
    REG_UNKNOWN,
}; 

const char* getRegisterName(DecodedRegister_t reg);

DecodedRegister_t decodeVmRegisterReference(const uint8_t registerEncoded);