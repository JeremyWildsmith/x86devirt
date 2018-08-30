[BITS 32]

; Define variables in the data section
SECTION .DATA

; Code goes in the text section
SECTION .TEXT
	GLOBAL decryptInstruction 
	GLOBAL _decryptInstruction 

_decryptInstruction:
decryptInstruction:
        push esi
        push eax
        push ecx
        mov esi,dword [esp+0x10]
        xor ecx,ecx
    vm_test_vmed_01.411143:
        mov al,byte [esi]
        xor eax,dword [esp+0x18]
        xor al,cl
        sub al,cl
        sub al,0x45
        inc al
        sub al,cl
        sub al,0x75
        xor al,cl
        xor al,0xF8
        sub al,cl
        ror al,cl
        ror al,cl
        add al,cl
        xor al,cl
        dec al
        add al,0x43
        sub al,0x50
        add al,cl
        jmp vm_test_vmed_01.41116E

    vm_test_vmed_01.41116E:
        add al,cl
        jmp vm_test_vmed_01.411173
    
    vm_test_vmed_01.411173:
        jmp vm_test_vmed_01.411176
    
    vm_test_vmed_01.411176:
        ror al,cl
        xor al,cl
        jmp vm_test_vmed_01.41117D

    vm_test_vmed_01.41117D:
        jmp vm_test_vmed_01.411180

    vm_test_vmed_01.411180:
        jmp vm_test_vmed_01.411183

    vm_test_vmed_01.411183:
        xor al,0xCA
        jmp vm_test_vmed_01.411188
    
    vm_test_vmed_01.411188:
        jmp vm_test_vmed_01.41118B

    vm_test_vmed_01.41118B:
        sub al,cl
        sub al,cl
        add al,0xA9
        sub al,cl
        add al,cl
        xor al,0xE1
        add al,0x30
        sub al,cl
        jmp vm_test_vmed_01.41119E

    vm_test_vmed_01.41119E:
        xor al,0x77
        jmp vm_test_vmed_01.4111A3

    vm_test_vmed_01.4111A3:
        mov byte [esi],al
        inc ecx
        inc esi
        cmp ecx,dword [esp+0x14]
        jne vm_test_vmed_01.411143
        pop ecx
        pop eax
        pop esi
        ret 0xC