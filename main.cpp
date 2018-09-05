#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <udis86.h>
#include <stdexcept>

#include <iomanip>
#include <queue>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>

using namespace std;

#define MAX_INSTRUCTION_LENGTH 100
#define MAX_DISASSEMBLED_SIZE 100

const char* vmrSub = "VMR";

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

DecodedVmInstruction disassembleVmInstruction(const uint8_t* instrBuffer, uint32_t instrLength, uint32_t vmRelativeIp, const uint32_t baseAddress, const uint32_t dumpBase) {
    DecodedVmInstruction result;
    result.isDecoded = true;
    result.address = vmRelativeIp + dumpBase;
    result.controlDestination = 0;
    result.size = instrLength;
    result.type = DecodedInstructionType_t::INSTR_MISC;

    memcpy(result.bytes, instrBuffer, instrLength);

    switch(instrBuffer[0]) {
        case 0x4: //0xC
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
        case 0x19://3
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "call 0x%08X", operand1 + baseAddress);
            break;
        }
        case 0x73: //0x24
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
        case 0xD6: //A
        case 0x86: //8
        {
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            sprintf(result.disassembled, "mov %s, %s", vmrSub, getRegisterName(operandA));
            break;
        }
        case 0x91: //5
        {
            uint16_t operand1 = *((uint16_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "ret 0x%X", (uint32_t)operand1);
            result.type = DecodedInstructionType_t::INSTR_RETN;
            break;
        }
        case 0xB0://0x09
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "add %s, 0x%X", vmrSub, operand1);
            break;
        }
        case 0x4D://B
        {
            uint8_t operand1 = *((uint8_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "shl %s, 0x%X", vmrSub, operand1);
            break;
        }
        case 0x64: //0x1
        case 0xD: //0x0
        {
            uint8_t operand1 = instrBuffer[1];
            uint32_t operand2 = *((uint32_t*)(&instrBuffer[2]));

            sprintf(result.disassembled, "%s lbl_0x%08X", getJumpName(decodeVmJump(operand1)), vmRelativeIp + operand2 + dumpBase);
            result.type = DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP;
            result.controlDestination = vmRelativeIp + operand2 + dumpBase;
            break;
        }
        case 0xE3://0x1E
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "cmp dword [%s], 0x%X", vmrSub, operand);
            break;
        }
        case 0x94://D
        case 0x9B://E
        {

            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));

            sprintf(result.disassembled, "jmp lbl_0x%08X", vmRelativeIp + operand1 + dumpBase);
            result.controlDestination = vmRelativeIp + operand1 + dumpBase;
            result.type = DecodedInstructionType_t::INSTR_JUMP;
            break;
        }
        case 0xC6://0x22
        {
            sprintf(result.disassembled, "push dword [%s]", vmrSub);
            break;
        }
        case 0x93://7
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "mov %s, 0x%X", vmrSub, operand1);
            break;
        }
        case 0xC0://1F
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(result.disassembled, "mov dword [%s], 0x%X", vmrSub, operand1);
            break;
        }
        default:
            result.type = DecodedInstructionType_t::INSTR_UNKNOWN;
    }
    
    return result;
}

unsigned int decodeVmInstruction(DecodedVmInstruction* decodedBuffer, const uint8_t* vmMemory, const long vmMemorySize, uint32_t vmRelativeIp, 
                            const uint32_t baseAddress, const uint32_t dumpBase) {

    
    uint32_t instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    uint8_t instrBuffer[MAX_INSTRUCTION_LENGTH];

    if(instrLength > sizeof(instrBuffer))
        throw runtime_error("Instruction size larger than max size.");
    else if(instrLength + vmRelativeIp > vmMemorySize)
        throw runtime_error("Instruction is outside of virtual memory.");

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr length byte
            instrLength);
    
    decryptInstruction(instrBuffer, instrLength, vmRelativeIp);
    
    char disassembledBuffer[MAX_DISASSEMBLED_SIZE];
    DecodedInstructionType_t instrType = DecodedInstructionType_t::INSTR_UNKNOWN;

    if(*(unsigned short*)instrBuffer == 0xFFFF) {
        //Offset by 2 which removes the 0xFFFF part of the instruction.
        *decodedBuffer = disassembleVmInstruction(instrBuffer + 2, instrLength - 2, vmRelativeIp, baseAddress, dumpBase);
    } else {
        *decodedBuffer = disassemble86Instruction(instrBuffer, instrLength, dumpBase + vmRelativeIp);
    }
    
    return instrLength + 1;
}

void formatInstructionInfo(const DecodedVmInstruction& decodedInstruction) {
    printf("lbl_0x%08X: ", decodedInstruction.address);

    if(decodedInstruction.type == DecodedInstructionType_t::INSTR_UNKNOWN)
        printf("%-30s ;", "Failed to disassemble");
    else
        printf("%-30s ;", decodedInstruction.disassembled);

    for(unsigned int i = 0; i < decodedInstruction.size; i++) {
        printf("%02X ", decodedInstruction.bytes[i] & 0xFF);
    }

    printf("\n");
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

bool isInRegions(const std::vector<DisassembledRegion>& regions, uint32_t ip, uint32_t max = 0xFFFFFFFF) {
    for(auto& region : regions) {
        if(ip >= region.min && ip < region.max && !(region.max == max && region.min == ip))
            return true;
    }

    return false;
}

vector<DisassembledRegion> getDisassembleRegions(const uint8_t* vmMemory, const unsigned int vmMemorySize, const uint32_t initialIp, uint32_t dumpBase) {
    
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

        while(vmRelativeIp <= vmMemorySize) {

            DecodedVmInstruction instr;
            
            vmRelativeIp += decodeVmInstruction(&instr, vmMemory, vmMemorySize, vmRelativeIp, 0, dumpBase);
            
            if(instr.type == DecodedInstructionType_t::INSTR_UNKNOWN)
                throw runtime_error("Unknown instruction encountered");

            if(instr.type == DecodedInstructionType_t::INSTR_JUMP || instr.type == DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP)
                stubsToDisassemble.push(instr.controlDestination);
            
            if(instr.type == DecodedInstructionType_t::INSTR_RETN || instr.type == DecodedInstructionType_t::INSTR_JUMP)
                break;
        }

        current.max = vmRelativeIp;
        disassembledStubs.push_back(current);
    }

    //Now we must resolve all overlapping stubs
    for(auto it = disassembledStubs.begin(); it != disassembledStubs.end();) {
        if(isInRegions(disassembledStubs, it->min, it->max))
            disassembledStubs.erase(it++);
        else
            it++;
    }

    return disassembledStubs;
}

DecodedVmInstruction eliminateVmrFromSubset(vector<DecodedVmInstruction>::iterator start, vector<DecodedVmInstruction>::iterator end) {
    bool baseRegUsed = false;
    char baseRegBuffer[10];
    uint32_t multiplier = 1;
    uint32_t offset = 0;

    for(auto it = start; it != end; it++) {
        char* dereferencePointer = 0;

        if(!strncmp(it->disassembled, "mov VMR, 0x", 11)) {
            offset = strtoul(&it->disassembled[11], NULL, 16);
        } else if(!strncmp(it->disassembled, "mov VMR, ", 9)) {
            baseRegUsed = true;
            strcpy(baseRegBuffer, &it->disassembled[9]);
        } else if(!strncmp(it->disassembled, "add VMR, 0x", 11)) {
            offset += strtoul(&it->disassembled[11], NULL, 16);
        } else if(!strncmp(it->disassembled, "add VMR, ", 9)) {
            baseRegUsed = true;
            strcpy(baseRegBuffer, &it->disassembled[9]);
        } else if(!strncmp(it->disassembled, "shl VMR, 0x", 11)) {
            uint32_t shift = strtoul(&it->disassembled[11], NULL, 16);
            if(shift != 0)
                throw runtime_error("Not sure what to do with this...");
        }
    }

    auto lastInstruction = end - 1;
    string reconstructInstr(lastInstruction->disassembled);
    stringstream reconstructed;

    reconstructed << "[";

    if(baseRegUsed) {
        if(multiplier != 1)
            reconstructed << "0x" << hex << multiplier << " * ";

        reconstructed << baseRegBuffer;
    }

    if(offset != 0 || (!baseRegUsed))
        reconstructed <<  " + 0x" << hex << offset;
    
    reconstructed << "]";

    reconstructInstr.replace(reconstructInstr.find("[VMR]"), 5, reconstructed.str());

    DecodedVmInstruction result;

    result.isDecoded = true;
    result.address = start->address;
    result.size = 0;
    result.type = lastInstruction->type;
    strcpy(result.disassembled, reconstructInstr.c_str());

    return result;
}

vector<DecodedVmInstruction> eliminateVmr(vector<DecodedVmInstruction>& instructions) {
    auto itVmrStart = instructions.end();
    vector<DecodedVmInstruction> compactInstructionlist;

    for(auto it = instructions.begin(); it != instructions.end(); it++) {
        if(!strncmp("mov VMR,", it->disassembled, 8) && itVmrStart == instructions.end()) {
            itVmrStart = it;
        }else if(itVmrStart != instructions.end() && strstr(it->disassembled, "[VMR]") != 0)
        {
            compactInstructionlist.push_back(eliminateVmrFromSubset(itVmrStart, it + 1));
            itVmrStart = instructions.end();
        } else if (itVmrStart == instructions.end()) {
            compactInstructionlist.push_back(*it);
        }
    }

    return compactInstructionlist;
}

bool disassembleStub(const uint8_t* vmMemory, const unsigned int vmMemorySize, const uint32_t baseAddress, const uint32_t dumpBase, 
                        const uint32_t initialIp) {
    
    vector<DisassembledRegion> stubs = getDisassembleRegions(vmMemory, vmMemorySize, initialIp, dumpBase);
    vector<DecodedVmInstruction> instructions;
    for(auto& stub : stubs) {
        for(uint32_t vmRelativeIp = stub.min; vmRelativeIp < stub.max;) {

            DecodedVmInstruction instr;
            
            vmRelativeIp += decodeVmInstruction(&instr, vmMemory, vmMemorySize, vmRelativeIp, baseAddress, dumpBase);
            instructions.push_back(instr);

            if(instr.type == DecodedInstructionType_t::INSTR_UNKNOWN) {
                throw runtime_error("Unknown instruction encountered");
            }
        }
    }

    for(auto& i : eliminateVmr(instructions)) {
        formatInstructionInfo(i);
    }

    return true;
}

int main(int argc, char** args) {
    const uint32_t baseAddress = 0x400000;

    if(argc < 4) {
        printf("Arguments: <vm code dump> <dump base> <initial ip in hex> <vmr sub>\n");
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

    const uint32_t dumpBase = strtoul(args[2], NULL, 16);
    uint32_t vmInitialIp = strtoul(args[3], NULL, 16);

    printf(";X86devirt Disassembler, by Jeremy Wildsmith\n");
    printf(";Assumes image base is at 0x%08X\n\n", baseAddress);
    printf(";Attempting to decode instructions, starting from 0x%08X\n\n", vmInitialIp);
    printf("ORG 0x%08X\n", dumpBase);
    printf("[BITS 32]\n");
    try {
        if(!disassembleStub(vmMemory, vmMemorySize, baseAddress, dumpBase, vmInitialIp))
            return -1;
    } catch (runtime_error& e) {
        printf("Error occured: %s", e.what());
    }

    free(vmMemory);
    return 0;
}