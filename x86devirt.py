from x64dbgpy.pluginsdk import *
import x64dbgpy
import os
import subprocess
import yara
import distorm3
from time import sleep
import struct

devirtTool = os.path.join(os.path.dirname(os.path.realpath(__file__)), "x86virt-disasm.exe")
bufferBin = os.path.join(os.path.dirname(os.path.realpath(__file__)), "buffer.bin")

maxInstructions = "999999"

def findLabelLocation(labels, searchLabel):
    for l in labels:
        if(l["name"] == searchLabel):
            return l["address"]

    return None

def devirt(source, destination, size):
    global maxInstructions
    
    x64dbg._plugin_logputs("Dumping bytecode... ")
    sourceBuffer = Read(source, size)

    file = open(bufferBin, "wb")
    file.write(sourceBuffer)
    file.close()
    
    x64dbg._plugin_logputs("Invoking disassembler: " + devirtTool + " " + bufferBin + " " + hex(destination) + " " + hex(destination) + " " + maxInstructions + " " + "ecx false")
    disassembledOutput = subprocess.check_output([devirtTool, bufferBin, hex(destination), hex(destination), maxInstructions, "ecx", "false"])

    labels = []
    for instruction in disassembledOutput.splitlines():
        label, x86 = instruction.split(":")
        labels.append(label);

    assembleAddress = destination
    labelLocations = [];

    unresolvedLocations = []
    for instruction in disassembledOutput.splitlines():
        label, x86 = instruction.split(":")
        labelLocations.append({"name": label, "address": assembleAddress})
        
        if(not AssembleMem(assembleAddress, x86)):
            x64dbg._plugin_logputs("Unable to assemble: " + instruction)
            return -1
            
        out = x64dbg.DISASM_INSTR()
        x64dbg.DbgDisasmAt(assembleAddress, out)

        if(out.type == 1 and x86.find(" ") >= 0 and x86.find(",") < 0 and x86.find("[") < 0): #If is branching instruction with one operand that is not a pointer
            
            operation, operand = x86.split(" ")

            if(operand in labels):
                correctLocation = findLabelLocation(labelLocations, operand)
                if(correctLocation is not None):
                    #Correct control flow address
                    correctedInstruction = operation + " " + hex(correctLocation)
                    AssembleMem(assembleAddress, correctedInstruction)

                    out = x64dbg.DISASM_INSTR()
                    x64dbg.DbgDisasmAt(assembleAddress, out)
                else:
                    correctedInstruction = operation + " " + operand
                    AssembleMem(assembleAddress, correctedInstruction)
                    out = x64dbg.DISASM_INSTR()
                    x64dbg.DbgDisasmAt(assembleAddress, out)
                    unresolvedLocations.append({"address": assembleAddress, "label": operand, "operation": operation, "size": out.instr_size})
                    
        assembleAddress += out.instr_size

    for unresolved in unresolvedLocations:
        correctLocation = findLabelLocation(labelLocations, unresolved["label"])
        if(correctLocation is not None):
            address = unresolved["address"]
            correctedInstruction = unresolved["operation"] + " " + hex(correctLocation)
            AssembleMem(address, correctedInstruction)
            out = x64dbg.DISASM_INSTR()
            x64dbg.DbgDisasmAt(address, out)

            for x in range(out.instr_size + address, unresolved["size"] + address):
                AssembleMem(x, "nop")
                
        else:
            x64dbg._plugin_logputs("Unable to resolve jump!")


    return assembleAddress - destination

def findVmStub():
    rule = yara.compile(source='rule VmStub {strings: $hex_string = { 60 9C 9C 59 8B C4 8B 5C 24 24 8B 54 24 28 E8 00 00 00 00 5C 8B ?? ?? ?? ?? ?? ?? 55 8B EC 83 EC 2C 89 44 24 28 89 0C 24 33 C9 8D 7C 24 04 8B F2 46 8A 02 32 42 01 0F B6 C0 50 } condition: $hex_string}')
    buffer = GetMainModuleSectionList()
    for val in buffer:
        x64dbg._plugin_logputs("Scanning section: " + val.name)
        scanBuffer = Read(val.addr, val.size)
        matches = rule.match(data=scanBuffer)

        if(len(matches) <= 0):
             continue
        
        matchedStrings = matches[0].strings

        if(len(matchedStrings) == 1):
            vmStubMatch = matchedStrings[0]
            return vmStubMatch[0] + val.addr

    return None

def findVmStubCrossReferences(vmStub):
    #x64dbg has not provided an interface to their cross-reference functionality yet...
    #So... We're going to have to do this with signatures
    references = []
    signatureSize = 30
    rule = yara.compile(source='rule JumpToVmStub {strings: $hex_string = { E8 00 00 00 00 9C 81 6C ?? ?? ?? ?? ?? ?? 9D E8 00 00 00 00 9C 81 6C ?? ?? ?? ?? ?? ?? 9D } condition: $hex_string}')
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
    Register.EIP = oldEip
    Register.ESP += 8

    return {"bytecode": bytecode, "original":original}

def main():

    Message("This python script is an x86virt devirtualizer written by Jeremy Wildsmith. It has been published on the github page https://github.com/JeremyWildsmith/x86devirt")    
    result = MessageYesNo("This script should be run when EIP Matches the entrypoint (not OEP, just the correct entrypoint). Is EIP at OP? Press No to cancel.")

    if(result == False):
        return False

    Message("Now attempting to locate all present VM stubs and decrypt / devirtualize respective functions.")
    
    x64dbg._plugin_logputs("Python script to use the x86virt-disassembler tool to reconstruct and automatically devirtualize protected executables. Written by Jeremy Wildsmith, github repo: https://github.com/JeremyWildsmith/x86devirt")
    x64dbg._plugin_logputs("Scanning for the location of the VM Stub...")
    vmStub = findVmStub()

    if(vmStub is None):
        x64dbg._plugin_logputs("Failed to locate VM Stub. Exiting...")
        return

    x64dbg._plugin_logputs("VM Stub located at: " + hex(vmStub))
    x64dbg._plugin_logputs("Searching for cross references to VM Stub...")

    references = findVmStubCrossReferences(vmStub)
    x64dbg._plugin_logputs("Found " + str(len(references)) + " references... Emulating to get locations of encrypted sections")


    encryptedFunctions = []
    for r in references:
        x64dbg._plugin_logputs("Emulating reference at: " + hex(r["start"]))
        func = emulateAndFind(r["start"], r["jump"])
        func["reference"] = r
        x64dbg._plugin_logputs("Found encrypted function: " + hex(func["bytecode"]))
        encryptedFunctions.append(func)

    allocatedSections = {}
    for ef in encryptedFunctions:
        sectionAddress = ef["reference"]["section"].addr
        sectionSize = ef["reference"]["section"].size
        
        if(sectionAddress not in allocatedSections):
            allocatedDecryptAddress = 0
            tryAllocateAddress = 0x400000
            while(allocatedDecryptAddress == 0):
                allocatedDecryptAddress = RemoteAlloc(sectionSize, tryAllocateAddress)
                tryAllocateAddress += 0x10000
            
            allocatedSections[sectionAddress] = {"origin": allocatedDecryptAddress, "writeAddress": allocatedDecryptAddress}

        dumpSize = sectionSize - (ef["bytecode"] - sectionAddress)
        writeAddress = allocatedSections[sectionAddress]["writeAddress"]
        
        x64dbg._plugin_logputs("Decrypting function to: " + hex(writeAddress) + ", using dump size: " + str(dumpSize))

        assembleSize = devirt(ef["bytecode"], writeAddress, dumpSize)
        if(assembleSize < 0):
            x64dbg._plugin_logputs("Stopping unpacking, assemble operation failed.")
            return False

        allocatedSections[sectionAddress]["writeAddress"] += assembleSize
        
        x64dbg._plugin_logputs("Hijacking VM Entry for function " + hex(ef["reference"]["start"]) + " to decrypted function: " + hex(writeAddress))
        
        if(not AssembleMem(ef["reference"]["start"], "jmp " + hex(writeAddress))):
            x64dbg._plugin_logputs("Hijacking failed...")
            return False


    resultMessage = "Devirtualization was a success! You can now run or dump the application. Make sure you dump with the section(s) that contain the devirtualized code: "
    for key, val in allocatedSections.iteritems():
        resultMessage += hex(val["origin"]) + " "
        
    Message(resultMessage)
    return True
main()
