#include "decrypt.h"
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <udis86.h>

#define MAX_INSTRUCTION_LENGTH 100

typedef __attribute__((stdcall)) void (*DecryptInstruciton_t)(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset);

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

DecryptInstruciton_t fn_decryptInstruction = (DecryptInstruciton_t)(&decryptInstruction);

ud_t ud_obj;

uint32_t getInstructionLength(uint8_t* pInstructionBuffer) {
    return pInstructionBuffer[0] ^ pInstructionBuffer[1];
}

bool disassemble86Instruction(char* buffer, const uint8_t* instrBuffer, uint32_t instrLength) {

    ud_set_input_buffer(&ud_obj, instrBuffer, instrLength);
    ud_disassemble(&ud_obj);
    strcpy(buffer, ud_insn_asm(&ud_obj));

    return true;
}

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

const char* getRegisterName(DecodedRegister_t reg) {
    
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
        return "???";
    else
        return registerIndex[reg];   
}

DecodedJump_t decodeVmJump(const uint8_t jumpEncoded) {
    if(jumpEncoded < 0 || jumpEncoded > DecodedJump_t::JNB)
        return DecodedJump_t::JMP_UNKNOWN;

    return (DecodedJump_t)jumpEncoded;
}

DecodedRegister_t decodeVmRegisterReference(const uint8_t registerEncoded) {
    unsigned long reference = 0x5;
    reference = reference << 2;
    reference -= 0x20;
    reference ^= 0xFFFFFFFF;
    reference += 1;
    reference /= 4;

    if(reference < 0 || reference > DecodedRegister_t::EAX)
        return DecodedRegister_t::REG_UNKNOWN;

    return (DecodedRegister_t)reference;
}

bool disassembleVmInstruction(char* textBuffer, const uint8_t* instrBuffer, uint32_t instrLength, uint32_t vmRelativeIp, const uint32_t baseAddress) {
    switch(instrBuffer[0]) {
        case 0x4:
        {
            /*
             * Here we need to decode the VM instruction into a valid x86 instruction
             */
            uint32_t x86InstructionLength = instrLength + 3;

            uint8_t x86Buffer[x86InstructionLength];
            memcpy(x86Buffer, instrBuffer, instrLength);

            //89 05 04 89
            uint16_t operandsBuffer = *((uint16_t*)(&x86Buffer[1]));
            uint8_t* low = (uint8_t*)&operandsBuffer;
            uint8_t* high = ((uint8_t*)&operandsBuffer) + 1;

            *high = *high << 3;
            *high |= 5;

            //Here we copy the decoded instruction into the x86 buffer
            memcpy(x86Buffer, &operandsBuffer, 2);

            //We use a dummy pointer here (0xFFFFFFFF.) x86virt uses a pointer containing the value of VMR
            //So we will feed 0xFFFFFFFF into the disassembler and then replace it with VMR afterwards, since
            //the disassembler has no concept of the VMR
            uint32_t* ptr = (uint32_t*)(&x86Buffer[2]);
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
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(textBuffer, "call 0x%08X", operand1 + baseAddress);
            break;
        }
        case 0x73:
        {/*
            OPCODE 0x73 Handler at 004118B0

            OC OP1[byte] OP2[byte] OP3[Data...]
            OP3 is OP2 bytes in Length

            1. Copy OP2 Bytes from OP3  over start of instruction
            2. Add module base address (0x400000) to instructionat OP1 bytes in
            3. copy 0x68 into instruction at offset OP2

            */
            /*
             * Here we need to decode the VM instruction into a valid x86 instruction
             */
            uint32_t x86InstructionLength = instrLength + 2;

            uint8_t x86Buffer[x86InstructionLength];
            memcpy(x86Buffer, instrBuffer, instrLength);

            //Get operands needed for calculation
            const uint8_t op1 = x86Buffer[1];
            const uint8_t op2 = x86Buffer[2];

            uint8_t upperBuffer[op2];
            memcpy(upperBuffer, &x86Buffer[3], op2);
            memcpy(x86Buffer, upperBuffer, op2);
            *((unsigned long*)(&x86Buffer[op1])) += 0x400000;
            
            ud_set_input_buffer(&ud_obj, x86Buffer, x86InstructionLength);
            ud_disassemble(&ud_obj);
            strcpy(textBuffer, ud_insn_asm(&ud_obj));
            break;
        }
        case 0x86:
        {
            strcpy(textBuffer, "mov VMR, ");
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            strcat(textBuffer, getRegisterName(operandA));
            
            break;
        }
        case 0x91:
        {
            uint16_t operand1 = *((uint16_t*)(&instrBuffer[1]));
            sprintf(textBuffer, "ret 0x%X", (uint32_t)operand1);
            break;
        }
        case 0xB0:
        {
            strcpy(textBuffer, "add VMR, ");
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(textBuffer + strlen(textBuffer), "0x%X", operand1);
            break;
        }
        case 0xD:
        {
            uint8_t operand1 = instrBuffer[1];
            uint32_t operand2 = *((uint32_t*)(&instrBuffer[2]));

            sprintf(textBuffer, "%s 0x%08X", getJumpName(decodeVmJump(operand1)), vmRelativeIp + operand2);
            break;
        }
        case 0xE3:
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(textBuffer, "cmp [VMR], 0x%X", operand);
            break;
        }
        default:
            return false;
    }
    
    return true;
}

uint32_t formatInstructionInfo(uint8_t* vmMemory, const long vmMemorySize, uint32_t vmRelativeIp, const uint32_t baseAddress) {
    uint32_t instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    uint8_t instrBuffer[MAX_INSTRUCTION_LENGTH];

    if(instrLength > sizeof(instrBuffer))
        return 0;
    else if(instrLength + vmRelativeIp > vmMemorySize)
        return 0;

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr length byte
            instrLength);
    
    fn_decryptInstruction(instrBuffer, instrLength, vmRelativeIp);
    
    char disassembledBuffer[100];
    if(*(unsigned short*)instrBuffer == 0xFFFF) {
        //Offset by 2 which removes the 0xFFFF part of the instruction.
        bool success = disassembleVmInstruction(disassembledBuffer, instrBuffer + 2, instrLength - 2, vmRelativeIp, baseAddress);
        printf("\e[1;31m%08X - %-30s", vmRelativeIp, success ? disassembledBuffer : "Failed to disassemble");
    } else {
        bool success = disassemble86Instruction(disassembledBuffer, instrBuffer, instrLength);
        printf("%08X - %-30s", vmRelativeIp, success ? disassembledBuffer : "Failed to disassemble");
    }

    for(unsigned int i = 0; i < instrLength; i++) {
        printf("%02X ", instrBuffer[i] & 0xFF);
    }

    printf("\e[m\n");

    return instrLength + 1;
}

uint8_t* readVmMemory(const char* fileName, long* pSize) {
    FILE *f = fopen(fileName, "rb");

    if(!f)
        return 0;

    fseek(f, 0, SEEK_END);
    *pSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* vmMemory = (uint8_t*)malloc(*pSize + 1);
    fread(vmMemory, *pSize, 1, f);
    fclose(f);

    return vmMemory;
}

int main(int argc, char** args) {
    const uint32_t baseAddress = 0x400000;

    printf("X86devirt Disassembler, by Jeremy Wildsmith\n");

    printf("Arguments: <vm code dump> <initial ip in hex> <# instructions to decode>\n");

    if(argc < 4) {
        printf("Incorrect number of arguments...\n");
        return -1;
    }

    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);

    long vmMemorySize = 0;
    uint8_t* vmMemory = readVmMemory(args[1], &vmMemorySize);

    if(!vmMemory) {
        printf("Unable to load VM Memory...\n");
        return -1;
    }

    const unsigned int numInstructionsToDecode = atoi(args[3]);
    unsigned int vmRelativeIp = (int)strtol(args[2], NULL, 16);

    printf("Assumes image base is at 0x%08X\n", baseAddress);
    printf("Attempting to decode %d instructions, starting from 0x%08X\n\n", numInstructionsToDecode, vmRelativeIp);

    for(int i = 0; i < atoi(args[3]); i++) {
        uint32_t length = formatInstructionInfo(vmMemory, vmMemorySize, vmRelativeIp, baseAddress);

        if(length == 0) {
            printf("Decoding stopped due to invalid opcodes or end of VM Memory...\n");
            break;
        }

        vmRelativeIp += length;
    }

    free(vmMemory);
    return 0;
}