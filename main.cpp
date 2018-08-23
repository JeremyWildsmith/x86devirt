#include "decrypt.h"
#include <memory.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

typedef __attribute__((stdcall)) void (*DecryptInstruciton_t)(void* pInstrBufferOffset1, unsigned int instrLengthMinusOne, unsigned int relativeOffset);

DecryptInstruciton_t fn_decryptInstruction = (DecryptInstruciton_t)(&decryptInstruction);

unsigned int getInstructionLength(unsigned char* pInstructionBuffer) {
    return pInstructionBuffer[0] ^ pInstructionBuffer[1];
}

unsigned int executeInstruction(unsigned char* vmMemory, unsigned int vmRelativeIp) {
    unsigned int instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    unsigned char instrBuffer[instrLength];

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr lenght byte
            instrLength);
    
    fn_decryptInstruction(instrBuffer, instrLength, vmRelativeIp);

    printf("Executed instruction: ");

    for(char b : instrBuffer) {
        printf("%X,", b & 0xFF);
    }
    
    printf("\n");

    return instrLength + 1;
}

unsigned char* readVmMemory() {
    FILE *f = fopen("virtualized_00412D5C.bin", "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char* vmMemory = (unsigned char*)malloc(fsize + 1);
    fread(vmMemory, fsize, 1, f);
    fclose(f);

    return vmMemory;
}

int main() {

    unsigned char* vmMemory = readVmMemory();

    unsigned int vmRelativeIp = 0;
    for(int i = 0; i < 6; i++) {
        vmRelativeIp += executeInstruction(vmMemory, vmRelativeIp);
    }
    free(vmMemory);
    return 0;
}