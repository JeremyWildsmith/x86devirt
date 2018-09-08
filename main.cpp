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

typedef __attribute__((stdcall)) void (*decryptInstruction_t)(void* pInstrBufferOffset1, uint32_t instrLengthMinusOne, uint32_t relativeOffset);

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
    INSTR_STOP,
    INSTR_COMMENT,
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

    DecodedVmInstruction() {
        isDecoded = false;
        strcpy(disassembled, ";Empty Instruction...");
        address = 0;
        size = 0;
        controlDestination = 0;
        type = INSTR_COMMENT;
    }
};

struct DisassembledRegion {
    uint32_t min;
    uint32_t max;
};

ud_t ud_obj;

uint32_t getInstructionLength(const uint8_t* pInstructionBuffer) {
    return pInstructionBuffer[0] ^ pInstructionBuffer[1];
}

vector<DecodedVmInstruction> disassemble86Instruction(const uint8_t* instrBuffer, uint32_t instrLength, const uint32_t instrAddress) {
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

    vector<DecodedVmInstruction> resultSet;
    resultSet.push_back(result);

    return resultSet;
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

vector<DecodedVmInstruction> disassembleVmInstruction(const uint8_t* instrBuffer, uint32_t instrLength, uint32_t vmRelativeIp, const uint32_t baseAddress, const uint32_t dumpBase, uint8_t* jmpMap) {
    vector<DecodedVmInstruction> resultSet;

    DecodedVmInstruction baseInstr;
    baseInstr.isDecoded = true;
    baseInstr.address = vmRelativeIp + dumpBase;
    baseInstr.controlDestination = 0;
    baseInstr.size = instrLength;
    baseInstr.type = DecodedInstructionType_t::INSTR_MISC;

    memcpy(baseInstr.bytes, instrBuffer, instrLength);

    switch(instrBuffer[0]) {
        case 0:
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
            strcpy(baseInstr.disassembled, replacedPointerBuffer);
            resultSet.push_back(baseInstr);

            break;
        }
        case 1:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "call 0x%08X", operand1 + baseAddress);
            resultSet.push_back(baseInstr);
            break;
        }
        case 2:
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
            strcpy(baseInstr.disassembled, ud_insn_asm(&ud_obj));
            resultSet.push_back(baseInstr);
            break;
        }
        case 3:
        {
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            sprintf(baseInstr.disassembled, "add %s, %s", vmrSub, getRegisterName(operandA));
            resultSet.push_back(baseInstr);
            /*
            if(operandA == DecodedRegister_t::ESP) {
                DecodedVmInstruction addInstr = baseInstr;
                sprintf(addInstr.disassembled, "add %s, 0x8", vmrSub);
                resultSet.push_back(addInstr);
            }*/

            break;
        }
        case 4:
        {
            uint16_t operand1 = *((uint16_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "ret 0x%X", (uint32_t)operand1);
            baseInstr.type = DecodedInstructionType_t::INSTR_RETN;
            resultSet.push_back(baseInstr);
            break;
        }
        case 5:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "add %s, 0x%X", vmrSub, operand1);
            resultSet.push_back(baseInstr);
            break;
        }
        case 6:
        {
            uint8_t operand1 = *((uint8_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "shl %s, 0x%X", vmrSub, operand1);
            resultSet.push_back(baseInstr);
            break;
        }
        case 7:
        {
            uint8_t operand1 = jmpMap[instrBuffer[1]];
            uint32_t operand2 = *((uint32_t*)(&instrBuffer[2]));

            sprintf(baseInstr.disassembled, "%s lbl_0x%08X", getJumpName(decodeVmJump(operand1)), vmRelativeIp + operand2 + dumpBase);
            baseInstr.type = DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP;
            baseInstr.controlDestination = vmRelativeIp + operand2 + dumpBase;
            resultSet.push_back(baseInstr);
            break;
        }
        case 8:
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "cmp dword [%s], 0x%X", vmrSub, operand);
            resultSet.push_back(baseInstr);
            break;
        }
        case 9:
        {

            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));

            sprintf(baseInstr.disassembled, "jmp lbl_0x%08X", vmRelativeIp + operand1 + dumpBase);
            baseInstr.controlDestination = vmRelativeIp + operand1 + dumpBase;
            baseInstr.type = DecodedInstructionType_t::INSTR_JUMP;
            resultSet.push_back(baseInstr);
            break;
        }
        case 10:
        {
            sprintf(baseInstr.disassembled, "push dword [%s]", vmrSub);
            resultSet.push_back(baseInstr);
            break;
        }
        case 11:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "mov %s, 0x%X", vmrSub, operand1);
            resultSet.push_back(baseInstr);
            break;
        }
        case 12:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "mov dword [%s], 0x%X", vmrSub, operand1);
            resultSet.push_back(baseInstr);
            break;
        }
        case 13:
        {
            uint32_t operand1 = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "push 0x%08X", operand1 + baseAddress);
            resultSet.push_back(baseInstr);
            break;
        }
        case 14:
        {
            sprintf(baseInstr.disassembled, "pop dword [VMR]");
            resultSet.push_back(baseInstr);
            break;
        }
        case 15:
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "sub dword [%s], 0x%X", vmrSub, operand);
            resultSet.push_back(baseInstr);
            break;
        }
        case 16:
        {
            const uint32_t operand = *((uint32_t*)(&instrBuffer[1]));
            sprintf(baseInstr.disassembled, "STOP", vmrSub, operand);
            baseInstr.type = DecodedInstructionType_t::INSTR_STOP;
            resultSet.push_back(baseInstr);
            break;
        }
        case 17:
        {
            DecodedRegister_t operandA = decodeVmRegisterReference(instrBuffer[1]);
            sprintf(baseInstr.disassembled, "mov %s, %s", vmrSub, getRegisterName(operandA));
            resultSet.push_back(baseInstr);

            /*
            if(operandA == DecodedRegister_t::ESP) {
                DecodedVmInstruction addInstr = baseInstr;
                sprintf(addInstr.disassembled, "add %s, 0x8", vmrSub);
                resultSet.push_back(addInstr);
            }*/

            break;
        }
        default:
        {
            baseInstr.type = DecodedInstructionType_t::INSTR_UNKNOWN;
            resultSet.push_back(baseInstr);
        }
    }
    
    return resultSet;
}

unsigned int decodeVmInstruction(vector<DecodedVmInstruction>& decodedBuffer, const uint8_t* vmMemory, const long vmMemorySize, uint32_t vmRelativeIp, 
                            const uint32_t baseAddress, const uint32_t dumpBase, uint8_t* instructionMappings, decryptInstruction_t func_decryptInstruction, uint8_t* jmpMap) {

    uint32_t instrLength = getInstructionLength(vmMemory + vmRelativeIp);
    uint8_t instrBuffer[MAX_INSTRUCTION_LENGTH];

    if(instrLength > sizeof(instrBuffer))
        throw runtime_error("Instruction size larger than max size.");
    else if(instrLength + vmRelativeIp > vmMemorySize)
        throw runtime_error("Instruction is outside of virtual memory.");

    memcpy(instrBuffer,
            vmMemory + vmRelativeIp + 1, //Need to add 1 to offset from instr length byte
            instrLength);
    
    func_decryptInstruction(instrBuffer, instrLength, vmRelativeIp);
    
    char disassembledBuffer[MAX_DISASSEMBLED_SIZE];
    DecodedInstructionType_t instrType = DecodedInstructionType_t::INSTR_UNKNOWN;

    if(*(unsigned short*)instrBuffer == 0xFFFF) {
        //Offset by 2 which removes the 0xFFFF part of the instruction.
        
        //Map instructions correctly
        instrBuffer[2] = instructionMappings[instrBuffer[2]];
        decodedBuffer = disassembleVmInstruction(instrBuffer + 2, instrLength - 2, vmRelativeIp, baseAddress, dumpBase, jmpMap);
    } else {
        decodedBuffer = disassemble86Instruction(instrBuffer, instrLength, dumpBase + vmRelativeIp);
    }
    
    return instrLength + 1;
}

void formatInstructionInfo(const DecodedVmInstruction& decodedInstruction) {
    bool isComment = decodedInstruction.type == DecodedInstructionType_t::INSTR_COMMENT;

    printf("%s_0x%08X: ", isComment ? ";cm" : "lbl", decodedInstruction.address);

    if(decodedInstruction.type == DecodedInstructionType_t::INSTR_UNKNOWN)
        printf("%-30s ;", "Failed to disassemble");
    else
        printf("%-30s ;", decodedInstruction.disassembled);

    for(unsigned int i = 0; i < decodedInstruction.size; i++) {
        printf("%02X ", decodedInstruction.bytes[i] & 0xFF);
    }

    printf("\n");
}

uint8_t* readVmMemory(const char* fileName, long* pSize = 0) {
    long readSize = 0;
    FILE *f = fopen(fileName, "rb");

    if(!f)
        return 0;

    fseek(f, 0, SEEK_END);
    readSize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* vmMemory = (uint8_t*)malloc(readSize + 1);
    fread(vmMemory, readSize, 1, f);
    fclose(f);

    if(pSize)
        *pSize = readSize;

    return vmMemory;
}

bool isInRegions(const std::vector<DisassembledRegion>& regions, uint32_t ip, uint32_t max = 0xFFFFFFFF) {
    for(auto& region : regions) {
        if(ip >= region.min && ip < region.max && !(region.max == max && region.min == ip))
            return true;
    }

    return false;
}

vector<DisassembledRegion> getDisassembleRegions(const uint8_t* vmMemory, const unsigned int vmMemorySize, const uint32_t initialIp, uint32_t dumpBase, uint8_t* instructionMappings, decryptInstruction_t func_decryptInstruction, uint8_t* jmpMap) {
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

        bool continueDisassembling = true;
        while(vmRelativeIp <= vmMemorySize && continueDisassembling) {

            vector<DecodedVmInstruction> instrSet;
   
            vmRelativeIp += decodeVmInstruction(instrSet, vmMemory, vmMemorySize, vmRelativeIp, 0, dumpBase, instructionMappings, func_decryptInstruction, jmpMap);
    
            for(auto& instr : instrSet) {
                if(instr.type == DecodedInstructionType_t::INSTR_UNKNOWN) {
                    stringstream msg;
                    msg << "Unknown instruction encountered: 0x" << hex << ((unsigned long)instr.bytes[0]);
                    throw runtime_error(msg.str());
                }
                
                if(instr.type == DecodedInstructionType_t::INSTR_JUMP || instr.type == DecodedInstructionType_t::INSTR_CONDITIONAL_JUMP)
                    stubsToDisassemble.push(instr.controlDestination);
                
                if(instr.type == DecodedInstructionType_t::INSTR_STOP || instr.type == DecodedInstructionType_t::INSTR_RETN || instr.type == DecodedInstructionType_t::INSTR_JUMP)
                    continueDisassembling = false;
            }
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
    bool baseReg2Used = false;
    bool baseReg1Used = false;
    char baseReg1Buffer[10];
    char baseReg2Buffer[10];
    uint32_t multiplierReg1 = 1;
    uint32_t multiplierReg2 = 1;

    uint32_t offset = 0;

    for(auto it = start; it != end; it++) {
        char* dereferencePointer = 0;

        if(!strncmp(it->disassembled, "mov VMR, 0x", 11)) {
            offset = strtoul(&it->disassembled[11], NULL, 16);
            baseReg1Used = false;
            baseReg2Used = false;
            multiplierReg1 = multiplierReg2 = 1;
        } else if(!strncmp(it->disassembled, "mov VMR, ", 9)) {
            baseReg1Used = true;
            baseReg2Used = false;
            multiplierReg1 = multiplierReg2 = 1;
            offset = 0;
            strcpy(baseReg1Buffer, &it->disassembled[9]);
        } else if(!strncmp(it->disassembled, "add VMR, 0x", 11)) {
            offset += strtoul(&it->disassembled[11], NULL, 16);
        } else if(!strncmp(it->disassembled, "add VMR, ", 9)) {
            if(baseReg1Used) {
                baseReg2Used = true;
                strcpy(baseReg2Buffer, &it->disassembled[9]);
            } else {
                baseReg1Used = true;
                strcpy(baseReg1Buffer, &it->disassembled[9]);    
            }
        } else if(!strncmp(it->disassembled, "shl VMR, 0x", 11)) {
            uint32_t shift = strtoul(&it->disassembled[11], NULL, 16);
            offset = offset << shift;
            if(baseReg1Used) {
                multiplierReg1 = multiplierReg1 << shift;
            }
            if(baseReg2Used) {
                multiplierReg2 = multiplierReg2 << shift;
            }
        }
    }

    auto lastInstruction = end - 1;
    string reconstructInstr(lastInstruction->disassembled);
    stringstream reconstructed;

    reconstructed << "[";

    if(baseReg1Used) {
        if(multiplierReg1 != 1)
            reconstructed << "0x" << hex << multiplierReg1 << " * ";

        reconstructed << baseReg1Buffer;
    }

    if(baseReg2Used) {
        reconstructed << " + ";
        if(multiplierReg2 != 1)
            reconstructed << "0x" << hex << multiplierReg2 << " * ";

        reconstructed << baseReg2Buffer;
    }

    if(offset != 0 || !(baseReg1Used))
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
            for(auto listing = itVmrStart; listing != it+1; listing++) {
                DecodedVmInstruction comment = *listing;
                comment.type = INSTR_COMMENT;
                compactInstructionlist.push_back(comment);
            }
            compactInstructionlist.push_back(eliminateVmrFromSubset(itVmrStart, it + 1));
            itVmrStart = instructions.end();
        } else if (itVmrStart == instructions.end()) {
            compactInstructionlist.push_back(*it);
        }
    }

    return compactInstructionlist;
}


/*void sortRegionsAscending(vector<DisassembledRegion>& regions) {

}
*/

bool sortRegionsAscending (DisassembledRegion& a, DisassembledRegion& b) { 
    return a.min < b.min;
}
bool disassembleStub(const uint8_t* vmMemory, const unsigned int vmMemorySize, const uint32_t baseAddress, const uint32_t dumpBase, 
                        const uint32_t initialIp, uint8_t* instructionMappings, decryptInstruction_t func_decryptInstruction, uint8_t* jmpMap) {
    
    vector<DisassembledRegion> stubs = getDisassembleRegions(vmMemory, vmMemorySize, initialIp, dumpBase, instructionMappings, func_decryptInstruction, jmpMap);
    
    //Needs to be sorted, otherwise (due to jump sizes) may not fit into original location
    //Sorting should match it with the way it was implemented.
    sort(stubs.begin(), stubs.end(), sortRegionsAscending);

    if(stubs.empty()) {
        printf(";No stubs detected to disassemble.. %d", stubs.size());
        return true;
    }

    vector<DecodedVmInstruction> instructions;
    for(auto& stub : stubs) {
        
        bool continueDisassembling = true;
        DecodedVmInstruction blockMarker;
        blockMarker.type = DecodedInstructionType_t::INSTR_COMMENT;
        strcpy(blockMarker.disassembled, "BLOCK");
        instructions.push_back(blockMarker);
        for(uint32_t vmRelativeIp = stub.min; continueDisassembling && vmRelativeIp < stub.max;) {

            vector<DecodedVmInstruction> instrSet;
   
            vmRelativeIp += decodeVmInstruction(instrSet, vmMemory, vmMemorySize, vmRelativeIp, baseAddress, dumpBase, instructionMappings, func_decryptInstruction, jmpMap);

            for(auto& instr : instrSet) {
                if(instr.type == DecodedInstructionType_t::INSTR_UNKNOWN)
                    throw runtime_error("Unknown instruction encountered");
            
                if(instr.type == DecodedInstructionType_t::INSTR_STOP) {
                    continueDisassembling = false;
                    break;
                }
                
                instructions.push_back(instr);
            }

        }
        
        instructions.push_back(blockMarker);
    }

    for(auto& i : eliminateVmr(instructions)) {
        formatInstructionInfo(i);
    }

    return true;
}

int main(int argc, char** args) {
    const uint32_t baseAddress = 0x400000;

    if(argc < 7) {
        printf("Arguments: <vm code dump> <dump base> <initial ip in hex> <inst map dump> <decryptRoutineDump> <jmpMap>\n");
        printf("Incorrect number of arguments...\n");
        return -1;
    }

    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, 32);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);

    long vmMemorySize = 0;
    uint8_t* vmMemory = readVmMemory(args[1], &vmMemorySize);

    long mappingsSize = 0;
    uint8_t* instrMappings = readVmMemory(args[4], &mappingsSize);
    
    uint8_t* decryptRoutine = readVmMemory(args[5]);

    uint8_t* jmpMap = readVmMemory(args[6]);

    if(!decryptRoutine) {
        printf("Unable to load decrypt routine...");
        return -1;        
    }

    if(!instrMappings) {
        printf("Unable to load instruction mappings...");
        return -1;
    }

    if(mappingsSize != 0x100) {
        printf("Instruction mappings must be exactly 0x100 bytes... Current size is 0x%08X\n", mappingsSize);
        return -1;
    }

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
        if(!disassembleStub(vmMemory, vmMemorySize, baseAddress, dumpBase, vmInitialIp, instrMappings, (decryptInstruction_t)decryptRoutine, jmpMap))
            return -1;
    } catch (runtime_error& e) {
        printf("Error occured: %s", e.what());
    }

    free(instrMappings);
    free(vmMemory);
    return 0;
}