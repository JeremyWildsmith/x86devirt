from x64dbgpy.pluginsdk import *
import x64dbgpy
import os
import subprocess
import yara
import distorm3
from time import sleep
import struct
import angr

nasmTool = "nasm.exe"

bytecodeSignatures = [
    {
        "id": 1,
        "signature": "rule R {strings: $str = { } condition: $str}"
    }
]

def findLabelLocation(labels, searchLabel):
    for l in labels:
        if(l["name"] == searchLabel):
            return l["address"]

    return None

def devirt(source, destination, size, maxDestSize, mappingsLocation, decryptSubroutineDumpLocation):
    global maxInstructions

    outAsmName = "out_" + hex(destination) + ".asm";
    
    x64dbg._plugin_logputs("Dumping bytecode... ")
    sourceBuffer = Read(source, size)

    file = open("buffer.bin", "wb")
    file.write(sourceBuffer)
    file.close()
    
    x64dbg._plugin_logputs("Invoking disassembler: x86virt-disasm.exe buffer.bin " + hex(destination) + " " + hex(destination) + " " + mappingsLocation + " " + decryptSubroutineDumpLocation)
    disassembledOutput = subprocess.check_output(["x86virt-disasm.exe", "buffer.bin", hex(destination), hex(destination), mappingsLocation, decryptSubroutineDumpLocation])

    #Write disassembly to file
    file = open(outAsmName, "wb")
    file.write(disassembledOutput)
    file.close()

    x64dbg._plugin_logputs("Invoking nasm: nasm.exe -f bin " + outAsmName)
    disassembledOutput = subprocess.check_output(["nasm.exe", "-f", "bin", outAsmName])
	
    #Reading assembled bytes into buffer...
    file = open(os.path.splitext(outAsmName)[0], "rb")
    assembledCode = file.read()
    file.close()

    if(len(assembledCode) > maxDestSize):
        x64dbg._plugin_logputs("Error, destination of " + str(maxDestSize) + " is too small for " + str(len(assembledCode)))
        return 0
        
    x64dbg.Memory_Write(destination, assembledCode, len(assembledCode))
    x64dbg._plugin_logputs("It fits! Decrypted into " + hex(destination))
    #Get nasm to assemble it...
    return len(assembledCode)

def findVmStubs(rule):
    buffer = GetMainModuleSectionList()

    stubs = []
    for val in buffer:
        x64dbg._plugin_logputs("Scanning section: " + val.name)
        scanBuffer = Read(val.addr, val.size)
        matches = rule.match(data=scanBuffer)

        if(len(matches) <= 0):
             continue

        for m in matches:
            for vmStubMatch in m.strings:
                stubs.append(vmStubMatch[0] + val.addr)

    return stubs

def findVmStubCrossReferences(vmStub, rule):
    
    #x64dbg has not provided an interface to their cross-reference functionality yet...
    #So... We're going to have to do this with signatures
    references = []
    signatureSize = 30
    buffer = GetMainModuleSectionList()
    for val in buffer:
        x64dbg._plugin_logputs("Scanning section: " + val.name)
        scanBuffer = Read(val.addr, val.size)
        matches = rule.match(data=scanBuffer)

        for m in matches:
            matchedStrings = m.strings
            for referenceMatch in matchedStrings:
                instructionLocation = referenceMatch[0] + signatureSize;
                
                lastInstructionBuffer = scanBuffer[instructionLocation : instructionLocation + 10]
                
                decomposedInstructions = distorm3.Decompose(instructionLocation + val.addr, lastInstructionBuffer)
                vmReferenceInstruction = decomposedInstructions[0]
                
                if (vmReferenceInstruction.flowControl == "FC_UNC_BRANCH" and vmReferenceInstruction.operands[0].value == vmStub):                    
                    references.append({"start": referenceMatch[0] + val.addr, "jump": instructionLocation + val.addr, "section": val})

    return references


def emulateAndFind(startStub, jumpAddress):
    oldEip = Register.EIP
    SetEIP(startStub)
    SetBreakpoint(jumpAddress)
    debug.Run()
    DeleteBreakpoint(jumpAddress)
    original = struct.unpack("<L", Read(Register.ESP, 4))[0]
    bytecode = struct.unpack("<L", Read(Register.ESP + 4, 4))[0]

    #Seek upwards for jump to VM Stub
    jmpLocation = original - 5
    while(True):
        instrBuffer = Read(jmpLocation, 10)
        decomposedInstructions = distorm3.Decompose(jmpLocation, instrBuffer)
        if(decomposedInstructions[0].flowControl == "FC_UNC_BRANCH"):
            break;

        jmpLocation -= 1

    #Calculate available size...
    size = original - jmpLocation

    while(True):
        instrBuffer = ReadByte(original);
        if(instrBuffer == 0x90):
            size += 1
        else:
            break;

        original += 1

    Register.EIP = oldEip
    Register.ESP += 8

    return {"bytecode": bytecode, "original":jmpLocation, "size": size}

def determineInstructionFromHandler(handlerStub, instructionRules):
    handlerBuffer = Read(handlerStub, 200)
    matches = instructionRules.match(data=handlerBuffer)

    if(len(matches) <= 0):
        return None;

    for m in matches:
        for vmStubMatch in m.strings:
            if(vmStubMatch[0] != 0):
                continue
            
            handlerNo = int(vmStubMatch[1][2:])
            return handlerNo

    return None

def getInstructionMappings(vmStub, instructionRules):
    addressCalculateInstructionMappings = vmStub + 0xEF
    oldEip = Register.EIP
    oldEax = Register.EAX
    oldEdx = Register.EDX
    
    SetEIP(addressCalculateInstructionMappings)
    debug.StepOver()
    debug.StepOver()
    debug.StepOver()
    SetEIP(Register.EIP + 4)
    baseOfMap = Register.EAX

    startOfDispatch = Register.EIP
    mappings = bytearray(0xFF + 1)
    for i in range(0, 0xFF + 1):
        Register.EAX = baseOfMap
        Register.EDX = i

        debug.StepOver()
        debug.StepOver()
        debug.StepOver()
        debug.StepOver()
        debug.StepOver()
        
        handlerStub = Register.EAX
        mappedInstrNo = determineInstructionFromHandler(handlerStub, instructionRules)

        if(mappedInstrNo is not None):
            x64dbg._plugin_logputs("Matched opcode " + hex(i) + " to handler at :" + hex(handlerStub) + " for handler of instr no " + str(mappedInstrNo))
        else:
            mappedInstrNo = i
    
        mappings[i] = mappedInstrNo
        SetEIP(startOfDispatch)
    
    Register.EAX = oldEax
    Register.EIP = oldEip
    Register.EDX = oldEdx

    return mappings;

def getDecryptSubroutine(vmStub):
    addressCallDecrypt = vmStub + 0x44
    instrBuffer = Read(addressCallDecrypt, 10)
    decomposedInstructions = distorm3.Decompose(addressCallDecrypt, instrBuffer)
    decryptCall = decomposedInstructions[0]
    if (decryptCall.flowControl == "FC_CALL"):
        return decryptCall.operands[0].value;
    
    return None;

def dumpDecryptSubroutine(vmStub):
    outFileName = "decrypt.bin"
    decryptSubroutine = getDecryptSubroutine(vmStub)

    if(decryptSubroutine is None):
        return None
    
    decryptSubroutineBytes = Read(decryptSubroutine, 10000)
    decryptFile = open(outFileName, "wb")
    decryptFile.write(decryptSubroutineBytes)
    decryptFile.close()

    return outFileName

def dumpInstructionMap(vmStub, instructionRules):
    outFile = "instrmap.bin"
    mappings = getInstructionMappings(vmStub, instructionRules)

    if(mappings is None):
        return None
    
    mappingsFile = open(outFile, "wb")
    mappingsFile.write(mappings)
    mappingsFile.close()
    return outFile
    
def devirtVmStub(vmStub, yaraRules):

    x64dbg._plugin_logputs("Getting decrypt subroutine...")
    decryptSubroutine = dumpDecryptSubroutine(vmStub)

    if(decryptSubroutine is None):
        x64dbg._plugin_logputs("Unable to locate decrypt instruction subroutine, failed.")
        return False

    x64dbg._plugin_logputs("Extracting instruction mappings...")
    instructionMappings = dumpInstructionMap(vmStub, yaraRules["instructions"])

    x64dbg._plugin_logputs("VM Stub located at: " + hex(vmStub))
    x64dbg._plugin_logputs("Searching for cross references to VM Stub...")

    references = findVmStubCrossReferences(vmStub, yaraRules["vmRef"])
    x64dbg._plugin_logputs("Found " + str(len(references)) + " references... Emulating to get locations of encrypted sections")

    if len(references) == 0:
        x64dbg._plugin_logputs("VM Stub has no references, failed.")
        return False

    encryptedFunctions = []
    for r in references:
        x64dbg._plugin_logputs("Emulating reference at: " + hex(r["start"]))
        func = emulateAndFind(r["start"], r["jump"])
        func["reference"] = r
        x64dbg._plugin_logputs("Found encrypted function: " + hex(func["bytecode"]))
        encryptedFunctions.append(func)

    for ef in encryptedFunctions:
        sectionAddress = ef["reference"]["section"].addr
        sectionSize = ef["reference"]["section"].size
        dumpSize = sectionSize - (ef["bytecode"] - sectionAddress)
        x64dbg._plugin_logputs("Decrypting function from " + hex(ef["bytecode"]) + " to: " + hex(ef["original"]) + ", using dump size: " + str(dumpSize))

        assembleSize = devirt(ef["bytecode"], ef["original"], dumpSize, ef["size"], instructionMappings, decryptSubroutine)
        if(assembleSize < 0):
            x64dbg._plugin_logputs("Stopping unpacking, assemble operation failed.")
            return False
    
    return True

def tryDevirtAll(yaraRules):
    
    x64dbg._plugin_logputs("Scanning for the location of the VM Stub...")
    vmStubs = findVmStubs(yaraRules["vmStub"])

    if(len(vmStubs) == 0):
        x64dbg._plugin_logputs("Failed to locate any VM Stubs. Exiting...")
        return False;

    if(len(vmStubs) > 1):
        return False;
    
    for s in vmStubs:
        x64dbg._plugin_logputs("Attempting to devirt stub: " + hex(s))
        if(devirtVmStub(s, yaraRules) == False):
            x64dbg._plugin_logputs("Stopping unpacking, failed to devirt stub: " + hex(s))
            return False

    return True;

def extractJumpMap(jumpDecoder):
    jumpDecCalc = jumpDecoder + 0xA
    instructions = Read(jumpDecCalc, 0x100)

def main():
    #Message("This python script is an x86virt devirtualizer written by Jeremy Wildsmith. It has been published on the github page https://github.com/JeremyWildsmith/x86devirt")    
    #result = MessageYesNo("This script should be run when EIP Matches the entrypoint (not OEP, just the correct entrypoint). Is EIP at OP? Press No to cancel.")

    #if(result == False):
    #    return False
    
    #Message("Now attempting to locate all present VM stubs and decrypt / devirtualize respective functions.")

    os.chdir(os.path.dirname(os.path.realpath(__file__)))
    yaraRules = {
        "instructions": yara.compile(filepath='instructions.yara'),
        "vmStub": yara.compile(filepath='vmStub.yara'),
        "vmRef": yara.compile(filepath='vmRef.yara')
    }

    tryDevirtAll(yaraRules)
        
    Message("Application has been devirtualized, refer to log for more details...")


#main()
extractJumpMap(0x411000)
