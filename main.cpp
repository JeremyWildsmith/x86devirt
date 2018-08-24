#include "decrypt.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <udis86.h>

#define MAX_INSTRUCTION_LENGTH 100

typedef __attribute__((stdcall)) void (*DecryptInstruciton_t)(void* pInstrBufferOffset1, unsigned int instrLengthMinusOne, unsigned int relativeOffset);

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
    UNKNOWN,
};

DecryptInstruciton_t fn_decryptInstruction = (DecryptInstruciton_t)(&decryptInstruction);

ud_t ud_obj;

unsigned int getInstructionLength(unsigned char* pInstructionBuffer) {
    return pInstructionBuffer[0] ^ pInstructionBuffer[1];
}

bool disassemble86Instruction(char* buffer, const unsigned char* instrBuffer, unsigned int instrLength) {

    ud_set_input_buffer(&ud_obj, instrBuffer, instrLength);
    ud_disassemble(&ud_obj);
    strcpy(buffer, ud_insn_asm(&ud_obj));

    return true;
}

void concatRegister(char* textBuffer, DecodedRegister_t reg) {
    
    static const char* registerIndex[] = {
        "eflags",
        "edi",
        "esi",
        "ebp",
        "esp",
        "ebx",
        "edx",
        "ecx",
        "eax"
    };

    if(reg < 0 || reg > DecodedRegister_t::EAX)
        strcat(textBuffer, "???");
    else
        strcat(textBuffer, registerIndex[reg]);    
}

DecodedRegister_t decodeVmRegisterReference(const unsigned char registerEncoded) {
    unsigned long reference = 0x5;
    reference = reference << 2;
    reference -= 0x20;
    reference ^= 0xFFFFFFFF;
    reference += 1;
    reference /= 4;

    if(reference < 0 || reference > DecodedRegister_t::EAX)
        return DecodedRegister_t::UNKNOWN;

    return (DecodedRegister_t)reference;
}

char* disassembleVmOpcode(char* textBuffer, const unsigned char* instrBuffer, unsigned int instrLength) {
    switch(instrBuffer[0]) {
        case 0x4:
        {
            /*
             * Here we need to decode the VM instruction into a valid x86 instruction
             */
            unsigned int x86InstructionLength = instrLength + 3;

            unsigned char x86Buffer[x86InstructionLength];
            memcpy(x86Buffer, instrBuffer, instrLength);

            //89 05 04 89
            unsigned short operandsBuffer = *((unsigned short*)(&x86Buffer[1]));
            unsigned char* low = (unsigned char*)&operandsBuffer;
            unsigned char* high = ((unsigned char*)&operandsBuffer) + 1;

            *high = *high << 3;
            *high |= 5;

            //Here we copy the decoded instruction into the x86 buffer
            memcpy(x86Buffer, &operandsBuffer, 2);

            //We use a dummy pointer here (0xFFFFFFFF.) x86virt uses a pointer containing the value of VMR
            //So we will feed 0xFFFFFFFF into the disassembler and then replace it with VMR afterwards, since
            //the disassembler has no concept of the VMR
            unsigned long* ptr = (unsigned long*)(&x86Buffer[2]);
            *ptr = 0xFFFFFFFF;

            //here we disassemble the decided x86 instruction into the buffer
            char disassembledBuffer[100];
            ud_set_input_buffer(&ud_obj, x86Buffer, x86InstructionLength);
            ud_disassemble(&ud_obj);
            sprintf(disassembledBuffer, "%s", ud_insn_asm(&ud_obj));

            //And we replace the fake pointer
            const char* fakePointer = "0xffffffff";
            char* ptrLocation = strstr(disassembledBuffer, fakePointer);

            char replacedPointerBuffer[100];
            unsigned long firstLength = (ptrLocation - disassembledBuffer);

            memcpy(replacedPointerBuffer, disassembledBuffer, firstLength);
            replacedPointerBuffer[firstLength] = 0;
            strcat(replacedPointerBuffer, "VMR");
            strcat(replacedPointerBuffer, ptrLocation + strlen(fakePointer));
            strcpy(textBuffer, replacedPointerBuffer);

            break;
        }
        case 0x19:
            strcpy(textBuffer, "OPB ");
            break;
        case 0x73:
            strcpy(textBuffer, "OPC ");
            break;
        case 0x86:
        {
            strcpy(textBuffer, "ldr ");
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            concatRegister(textBuffer, operandA);
            
            break;
        }
        case 0x91:
            strcpy(textBuffer, "OPE ");
            break;
        case 0xB0:
        {
            strcpy(textBuffer, "add ");
            unsigned int operand1 = *((unsigned int*)(&instrBuffer[1]));
            sprintf(textBuffer + strlen(textBuffer), "%X", operand1);
            break;
        }
        case 0xD:
            strcpy(textBuffer, "OPG ");
            break;
        case 0xE3:
            strcpy(textBuffer, "OPH ");
            break;

        default:
            return 0;
    }
    
    return textBuffer;
}

bool disassembleVmInstruction(char* textBuffer, const unsigned char* instrBuffer, unsigned int instrLength) {
    char* disassembled = disassembleVmOpcode(textBuffer, instrBuffer + 2, instrLength - 2);
    
    return disassembled != 0;
}

unsigned int executeInstruction(unsigned char* vmMemory, unsigned int vmRelativeIp) {
    unsigned int instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    unsigned char instrBuffer[MAX_INSTRUCTION_LENGTH];

    if(instrLength > sizeof(instrBuffer)) {
        printf("Unexpected instruction length.");
        return 0;
    }

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr length byte
            instrLength);
    
    fn_decryptInstruction(instrBuffer, instrLength, vmRelativeIp);
    
    char disassembledBuffer[100];
    if(*(unsigned short*)instrBuffer == 0xFFFF) {
        bool success = disassembleVmInstruction(disassembledBuffer, instrBuffer, instrLength);
        printf("\e[1;31mV: %-30s", success ? disassembledBuffer : "Failed to disassemble");
    } else {
        bool success = disassemble86Instruction(disassembledBuffer, instrBuffer, instrLength);
        printf("R: %-30s", success ? disassembledBuffer : "Failed to disassemble");
    }

    for(unsigned int i = 0; i < instrLength; i++) {
        printf("%02X ", instrBuffer[i] & 0xFF);
    }

    printf("\e[m\n");

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
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);

    unsigned char* vmMemory = readVmMemory();

    unsigned int vmRelativeIp = 0;

    for(int i = 0; i < 10; i++) {
        vmRelativeIp += executeInstruction(vmMemory, vmRelativeIp);
    }

    free(vmMemory);
    return 0;
}