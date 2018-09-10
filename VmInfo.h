#pragma once
#include <memory>
#include <string>

typedef __attribute__((stdcall)) void (*decryptInstruction_t)(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset);

class VmInfo {
    
    std::unique_ptr<uint8_t[]> jmpMap;
    std::unique_ptr<uint8_t[]> opcodeMap;
    decryptInstruction_t func_decryptInstruction;
    uint32_t dumpBase;
    uint32_t imageBase;

    std::unique_ptr<uint8_t[]> dump;
    size_t dumpSize;
private:
    std::unique_ptr<uint8_t[]> func_decryptInstructionBuffer;
    std::unique_ptr<uint8_t[]> readFile(const std::string& fileName, size_t* pSize = 0);

public:
    VmInfo(std::string& dumpSource, uint32_t dumpBase, std::string& jmpMapSource, std::string& opcodeMapSource, std::string& decryptInstructionSource, uint32_t imageBase);
    
    std::unique_ptr<uint8_t[]> readMemory(uint32_t address, uint32_t size);
    void decryptMemory(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset);

    uint8_t getOpcodeMapping(uint8_t opcode);
    uint8_t getJmpMapping(uint8_t jmp);

    uint32_t getBaseAddress();
    uint32_t getImageBase();

    uint32_t getDumpSize();
};