from x64dbgpy.pluginsdk import *
import x64dbgpy
import struct
import time
import math
import os
import subprocess

devirtTool = os.path.join(os.path.dirname(os.path.realpath(__file__)), "x86virt-disasm.exe")
bufferBin = os.path.join(os.path.dirname(os.path.realpath(__file__)), "buffer.bin")

def findLabelLocation(labels, searchLabel):
    for l in labels:
        if(l["name"] == searchLabel):
            return l["address"]

    return None

def devirt(source, destination, size):
    
    x64dbg._plugin_logputs("Dumping bytecode... ")
    sourceBuffer = Read(source, size)

    file = open(bufferBin, "wb")
    file.write(sourceBuffer)
    file.close()
    disassembledOutput = subprocess.check_output([devirtTool, bufferBin, hex(destination), hex(destination), "100000", "ecx", "false"])

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
        
        AssembleMem(assembleAddress, x86)

        out = x64dbg.DISASM_INSTR()
        x64dbg.DbgDisasmAt(assembleAddress, out)

        if(out.type == 1 and x86.find(" ") >= 0 and x86.find(",") < 0 and x86.find("[") < 0): #If is branching instruction with one operand that is not a pointer
            
            operation, operand = x86.split(" ")
            x64dbg._plugin_logputs(operand)

            if(operand in labels):
                correctLocation = findLabelLocation(labelLocations, operand)
                if(correctLocation is not None):
                    #Correct control flow address
                    correctedInstruction = operation + " " + hex(correctLocation)
                    x64dbg._plugin_logputs("Corrected To: " + correctedInstruction)
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
            x64dbg._plugin_logputs("Corrected: " + correctedInstruction)
            AssembleMem(address, correctedInstruction)
            out = x64dbg.DISASM_INSTR()
            x64dbg.DbgDisasmAt(address, out)

            for x in range(out.instr_size + address, unresolved["size"] + address):
                AssembleMem(x, "nop")
                
        else:
            x64dbg._plugin_logputs("Unable to resolve jump!")
    return

        
            
def main():
    global continueTracing
    global traceLog

    
    out = x64dbg.DISASM_INSTR()
    x64dbg.DbgDisasmAt(0x00411A5D, out)
    x64dbg._plugin_logputs(str(out.type))
    #toolPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "asdf.exe")
    #x64dbg._plugin_logputs(toolPath)

main()
