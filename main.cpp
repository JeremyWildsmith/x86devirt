#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <udis86.h>

#include <queue>
#include <vector>
#include <algorithm>

using namespace std;

#define MAX_INSTRUCTION_LENGTH 100
#define MAX_DISASSEMBLED_SIZE 100

extern "C" __attribute__((stdcall)) void decryptInstruction(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset);

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

enum DecodedInstructionType_t {
    INSTR_UNKNOWN,
    INSTR_RETN,
    INSTR_JUMP,
    INSTR_CONDITIONAL_JUMP,
    INSTR_MISC,
};

struct DecodedVmInstruction {
    DecodedInstructionType_t type;
    bool isDecoded;
    char disassembled[MAX_DISASSEMBLED_SIZE];
    uint32_t address;
    uint8_t bytes[MAX_INSTRUCTION_LENGTH];
    uint8_t size;
    uint32_t controlDestination;
};

struct DisassembledRegion {
    uint32_t min;
    uint32_t max;
};

ud_t ud_obj;

uint32_t getInstructionLength(const uint8_t* pInstructionBuffer) {
    return pInstructionBuffer[0] ^ pInstructionBuffer[1];
}

DecodedVmInstruction disassemble86Instruction(const uint8_t* instrBuffer, uint32_t instrLength, const uint32_t instrAddress) {
    DecodedVmInstruction result;
    result.isDecoded = false;
    result.address = instrAddress;
    result.controlDestination = 0;
    result.size = instrLength;

    memcpy(result.bytes, instrBuffer, instrLength);
    
    ud_set_input_buffer(&ud_obj, instrBuffer, instrLength);
    ud_set_pc(&ud_obj, instrAddress);
    unsigned int ret = ud_disassemble(&ud_obj);
    strcpy(result.disassembled, ud_insn_asm(&ud_obj));

    if(ret == 0)
        result.type = DecodedInstructionType_t::INSTR_UNKNOWN;
    else
        result.type = (!strncmp(result.disassembled, "ret", 3) ? DecodedInstructionType_t::INSTR_RETN : DecodedInstructionType_t::INSTR_MISC);

    return result;
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
    unsigned long reference = registerEncoded;
    reference = reference << 2;
    reference -= 0x20;
    reference ^= 0xFFFFFFFF;
    reference += 1;
    reference /= 4;

    if(reference < 0 || reference > DecodedRegister_t::EAX)
        return DecodedRegister_t::REG_UNKNOWN;

    return (DecodedRegister_t)reference;
}

DecodedVmInstruction disassembleVmInstruction(const uint8_t* instrBuffer, uint32_t instrLength, uint32_t vmRelativeIp, const uint32_t baseAddress, const uint32_t dumpBase, const char* vmrSub) {
    DecodedVmInstruction result;
    result.isDecoded = true;
    result.address = vmRelativeIp + dumpBase;
    result.controlDestination = 0;
    result.size = instrLength;
    result.type = DecodedInstructionType_t::INSTR_MISC;

    memcpy(result.bytes, instrBuffer, instrLength);

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
            strcat(replacedPointerBuffer, vmrSub);
            strcat(replacedPointerBuffer, ptrLocation + strlen(fakePointer));
            strcpy(result.disassembled, replacedPointerBuffer);

            break;
        }
        case 0x19:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "call 0x%08X", operand1 + baseAddress);
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
            strcpy(result.disassembled, ud_insn_asm(&ud_obj));
            break;
        }
        case 0x86:
        {
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            sprintf(result.disassembled, "mov %s, %s", vmrSub, getRegisterName(operandA));
            break;
        }
        case 0x91:
        {
            uint16_t operand1 = *((uint16_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "ret 0x%X", (uint32_t)operand1);
            result.type = DecodedInstructionType_t::INSTR_RETN;
            break;
        }
        case 0xB0:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "add %s, 0x%X", vmrSub, operand1);
            break;
        }
        case 0x64:
        case 0xD:
        {
            uint8_t operand1 = instrBuffer[1];
            uint32_t operand2 = *((uint32_t*)(&instrBuffer[2]));

            sprintf(result.disassembled, "%s 0x%08X", getJumpName(decodeVmJump(operand1)), vmRelativeIp + operand2 + dumpBase);
            result.type = DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP;
            result.controlDestination = vmRelativeIp + operand2 + dumpBase;
            break;
        }
        case 0xE3:
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "cmp dword [%s], 0x%X", vmrSub, operand);
            break;
        }
        case 0x94:
        case 0x9B:
        {

            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));

            sprintf(result.disassembled, "jmp 0x%08X", vmRelativeIp + operand1 + dumpBase);
            result.controlDestination = vmRelativeIp + operand1 + dumpBase;
            result.type = DecodedInstructionType_t::INSTR_JUMP;
            break;
        }
        case 0xC6:
        {
            sprintf(result.disassembled, "push dword [%s]", vmrSub);
            break;
        }
        default:
            result.type = DecodedInstructionType_t::INSTR_UNKNOWN;
    }
    
    return result;
}

bool decodeVmInstruction(DecodedVmInstruction* decodedBuffer, const uint8_t* vmMemory, const long vmMemorySize, uint32_t vmRelativeIp, 
                            const uint32_t baseAddress, const uint32_t dumpBase, const char* vmrSub) {

    
    uint32_t instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    uint8_t instrBuffer[MAX_INSTRUCTION_LENGTH];

    if(instrLength > sizeof(instrBuffer))
        return false;
    else if(instrLength + vmRelativeIp > vmMemorySize)
        return false;

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr length byte
            instrLength);
    
    decryptInstruction(instrBuffer, instrLength, vmRelativeIp);
    
    char disassembledBuffer[MAX_DISASSEMBLED_SIZE];
    DecodedInstructionType_t instrType = DecodedInstructionType_t::INSTR_UNKNOWN;

    if(*(unsigned short*)instrBuffer == 0xFFFF) {
        //Offset by 2 which removes the 0xFFFF part of the instruction.
        *decodedBuffer = disassembleVmInstruction(instrBuffer + 2, instrLength - 2, vmRelativeIp, baseAddress, dumpBase, vmrSub);
        decodedBuffer->size += 2; // Add two for truncated 0xFFFF part.
    } else {
        *decodedBuffer = disassemble86Instruction(instrBuffer, instrLength, dumpBase + vmRelativeIp);
    }
    decodedBuffer->size += 1; //Add one byte for length byte.

    return true;
}

void formatInstructionInfo(const DecodedVmInstruction& decodedInstruction) {
  
    if(decodedInstruction.isDecoded)
        printf("\e[38;5;82m");

    if(decodedInstruction.type == DecodedInstructionType_t::INSTR_UNKNOWN)
        printf("%08X - %-30s", decodedInstruction.address, "Failed to disassemble");
    else
        printf("%08X - %-30s", decodedInstruction.address, decodedInstruction.disassembled);

    for(unsigned int i = 0; i < decodedInstruction.size; i++) {
        printf("%02X ", decodedInstruction.bytes[i] & 0xFF);
    }

    printf("\e[m\n");
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

bool isInRegions(const std::vector<DisassembledRegion>& regions, uint32_t ip) {
    for(auto& region : regions) {
        if(ip >= region.min && ip < region.max)
            return true;
    }

    return false;
}

void disassembleStub(const uint8_t* vmMemory, const unsigned int vmMemorySize, const uint32_t baseAddress, const uint32_t dumpBase, 
                        const uint32_t initialIp, unsigned int numInstructionsToDecode, 
                        const char* vmrSub, bool prettyPrint) {
    
    vector<DisassembledRegion> disassembledStubs;
    queue<uint32_t> stubsToDisassemble;
    stubsToDisassemble.push(initialIp);


    while(!stubsToDisassemble.empty()) {
        uint32_t vmRelativeIp = stubsToDisassemble.front() - dumpBase;
        stubsToDisassemble.pop();

        if(isInRegions(disassembledStubs, vmRelativeIp))
            continue;

        DisassembledRegion current;
        current.min = vmRelativeIp;

        for(int i = 0; i < numInstructionsToDecode; i++) {
            DecodedVmInstruction instr;

            bool successful = decodeVmInstruction(&instr, vmMemory, vmMemorySize, vmRelativeIp, baseAddress, dumpBase, vmrSub);
            vmRelativeIp += instr.size;

            if(!successful) {
                printf("Decoding stopped due to invalid opcodes, or encountered end of VM Memory...\n");
                break;
            }

            if(prettyPrint)
                formatInstructionInfo(instr);
            else
                printf("0x%08X:%s\n", instr.address, instr.disassembled);

            if(instr.type == DecodedInstructionType_t::INSTR_JUMP || instr.type == DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP)
                stubsToDisassemble.push(instr.controlDestination);
            
            if(instr.type == DecodedInstructionType_t::INSTR_RETN || instr.type == DecodedInstructionType_t::INSTR_JUMP)
                break;
        }

        current.max = vmRelativeIp;
        disassembledStubs.push_back(current);
    }
}

int main(int argc, char** args) {
    const uint32_t baseAddress = 0x400000;

    if(argc < 5) {
        printf("Arguments: <vm code dump> <dump base> <initial ip in hex> <# instructions to decode> <vmr sub> <prettyPrint = true>\n");
        printf("Incorrect number of arguments...\n");
        return -1;
    }

    bool prettyPrint = true;
    if(argc >= 7) {
        if(!strcmp(args[6], "false"))
            prettyPrint = false;
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

    const uint32_t dumpBase = strtol(args[2], NULL, 16);
    const unsigned int numInstructionsToDecode = atoi(args[4]);
    uint32_t vmInitialIp = (uint32_t)strtol(args[3], NULL, 16);

    if(vmInitialIp < dumpBase || vmInitialIp >= dumpBase + vmMemorySize) {
        printf("IP is outside of bounds of Virtual Memory.\n");
        return -1;
    }

    const char* vmrSub = (argc >= 6 ? args[5] : "VMR");
    if(strlen(vmrSub) > 3 || strlen(vmrSub) < 1) {
        printf("VMR Sub must be a maximum of 3 characters and a minimum of 1\n");
        return -1;   
    }

    if(prettyPrint) {
        printf("X86devirt Disassembler, by Jeremy Wildsmith\n");
        printf("Assumes image base is at 0x%08X\n\n", baseAddress);
        printf("Substituting VMR with %s\n\n", vmrSub);
        printf("Instructions not coloured green are decrypted x86 instructions without decoding or interpreting.\n\n");
        printf("Attempting to decode %d instructions, starting from 0x%08X\n\n", numInstructionsToDecode, vmInitialIp);
    }
    
    disassembleStub(vmMemory, vmMemorySize, baseAddress, dumpBase, vmInitialIp, numInstructionsToDecode, vmrSub, prettyPrint);

    free(vmMemory);
    return 0;
}