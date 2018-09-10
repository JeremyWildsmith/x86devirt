#include "VmInfo.h"
#include "VmJmp.h"

#include <memory.h>

#include <fstream>
#include <stdexcept>
#include <sstream>
#include <iostream>

using namespace std;

VmInfo::VmInfo(std::string& dumpSource, uint32_t dumpBase, std::string& jmpMapSource, std::string& opcodeMapSource, std::string& decryptInstructionSource, uint32_t imageBase) {
    dump = readFile(dumpSource, &this->dumpSize);
    
    size_t readSize = 0;
    jmpMap = readFile(jmpMapSource, &readSize);

    if(readSize < JMP_UNKNOWN) {
        stringstream err("Jump map is too small. Must be at least ");
        err << static_cast<int>(JMP_UNKNOWN) << " bytes in size.";
        throw runtime_error(err.str());
    }

    opcodeMap = readFile(opcodeMapSource, &readSize);

    if(readSize < 0x100)
        throw runtime_error("Opcode map is too small. Must be at least 0x100 bytes in size");
    
    func_decryptInstructionBuffer = readFile(decryptInstructionSource);
    
    this->func_decryptInstruction = (decryptInstruction_t)(func_decryptInstructionBuffer.get());

    this->dumpBase = dumpBase;
    this->imageBase = imageBase;
}


std::unique_ptr<uint8_t[]> VmInfo::readFile(const string& fileName, size_t* pSize) {
    ifstream fin(fileName, ios::in | ios::binary );

    if(!fin)
        throw runtime_error(string("Error opening file for reading: ") + fileName);

    auto startPos = fin.tellg();
    fin.seekg( 0, ios::end );
    size_t fsize = fin.tellg() - startPos;
    fin.seekg(0, std::ios::beg);

    unique_ptr<uint8_t[]> vmMemory(new uint8_t[fsize]);
    if(!fin.read((char*)vmMemory.get(), fsize))
        throw runtime_error("Error reading file...");

    fin.close();
    
    if(pSize)
        *pSize = fsize;

    return vmMemory;
}

std::unique_ptr<uint8_t[]> VmInfo::readMemory(uint32_t address, uint32_t size) {
    if(address < this->dumpBase || address + size > this->dumpBase + this->dumpSize)
        throw runtime_error("Reading out of memory dump");

    uint32_t relativeAddress = address - this->dumpBase;

    unique_ptr<uint8_t[]> readBuffer(new uint8_t[size]);
    memcpy(readBuffer.get(), dump.get() + relativeAddress, size);
    
    return readBuffer;
}

void VmInfo::decryptMemory(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset) {
    this->func_decryptInstruction(pInstrBufferOffset1, instrLengthMinusOne, relativeOffset);
}

uint8_t VmInfo::getOpcodeMapping(uint8_t opcode) {
    return this->opcodeMap[opcode];
}

uint8_t VmInfo::getJmpMapping(uint8_t jmp) {
    if(jmp >= JMP_UNKNOWN)
        throw runtime_error("Jump index outside of allowed range.");

    return this->jmpMap[jmp];
}

uint32_t VmInfo::getBaseAddress() {
    return this->dumpBase;
}

uint32_t VmInfo::getImageBase() {
    return this->imageBase;
}

uint32_t VmInfo::getDumpSize() {
    return this->dumpSize;
}