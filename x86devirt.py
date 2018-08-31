from x64dbgpy.pluginsdk import *
import x64dbgpy
import struct
import time
import math
import os
import subprocess

devirtTool = os.path.join(os.path.dirname(os.path.realpath(__file__)), "x86virt-disasm.exe")
bufferBin = os.path.join(os.path.dirname(os.path.realpath(__file__)), "buffer.bin")
    
def devirt(source, destination, size):
    
    x64dbg._plugin_logputs("Dumping bytecode... ")
    sourceBuffer = Read(source, size)

    file = open(bufferBin, "wb")
    file.write(sourceBuffer)
    file.close()
    disassembledOutput = subprocess.check_output([devirtTool, bufferBin, hex(destination), hex(destination), "100000", "ecx", "false"])

    assembleAddress = destination
    for instruction in disassembledOutput.splitlines():
        if(instruction.startswith("Decoding stopped")):
            continue
        x64dbg._plugin_logputs(instruction)
        AssembleMem(assembleAddress, instruction)

        out = x64dbg.DISASM_INSTR()
        x64dbg.DbgDisasmAt(assembleAddress, out)
        assembleAddress += out.instr_size

        
    return

        
            
def main():
    global continueTracing
    global traceLog

    toolPath = os.path.join(os.path.dirname(os.path.realpath(__file__)), "asdf.exe")
    x64dbg._plugin_logputs(toolPath)

main()
