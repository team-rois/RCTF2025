



源码:

```c++
// CTFtopic.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "ntdll.h"
#include "rc4.h"
using namespace std;

#pragma comment(linker, "/INCLUDE:__tls_used")

typedef NTSTATUS(NTAPI* _NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
    );

struct MyKeyFlag
{
    DWORD AddressFlag;
    char keybuffer[128];
};

MyKeyFlag KeyFlah = { 0x12345678,'f','l','a','g',':','{','T','h','1','s','f','l','a','g','l','s','G','0','0','d','s','}',0 };
int g_keyptrIndex = 0;
char* keyAddress;



void testNtPort(_NtQueryInformationProcess NtQueryInformationProcess);
void testCloseHandle(_NtQueryInformationProcess NtQueryInformationProcess);
void testFlag(_NtQueryInformationProcess NtQueryInformationProcess);
char* FindKeyAddress();
int testBeginDebugged();
int testNtGlobalFlag();

void NTAPI TLS_CALLBACK1(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    char szMsg[80] = { 0, };
    wsprintfA(szMsg, "() : DllHandle = %X, Reason = %d\n", DllHandle, Reason);

}

void NTAPI TLS_CALLBACK2(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    char szMsg[80] = { 0, };
    wsprintfA(szMsg, "() : DllHandle = %X, Reason = %d\n", DllHandle, Reason);
    testBeginDebugged();
}

#pragma data_seg(".CRT$XLX")

PIMAGE_TLS_CALLBACK pTLS_CALLBACKs[] = { TLS_CALLBACK1, TLS_CALLBACK2, 0 };
#pragma data_seg()



int testBeginDebugged()
{
 

    if (IsDebuggerPresent())
    {
       
        exit(0);
    }
    else
    {
        
    }
    FindKeyAddress();
    return 1;
}

int testNtGlobalFlag()
{
    __asm {
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    DWORD p;
    _asm
    {
        call l1
        l1 :
        pop eax
            mov p, eax
            call f1
            _EMIT 0xEA
            jmp l2
            f1 :
        pop ebx
            inc ebx
            push ebx
            mov eax, 0x11111111
            ret
            l2 :
        call f2
            mov ebx, 0x33333333
            jmp e
            f2 :
        mov ebx, 0x11111111
            pop ebx
            mov ebx, offset e
            push ebx
            ret
            e :
        mov ebx, 0x22222222
    }
    bool IsDebug = 1;
    __asm
    {
        push eax
        mov eax, fs: [0x30]
        mov al, byte ptr[eax+2]
        mov IsDebug,al
        pop eax
    }
    FindKeyAddress();

    g_keyptrIndex = 8;
    if (IsDebug)
    {

    }
    else
    {
        keyAddress[g_keyptrIndex] = 'i';
    }

    return p;

}


BOOL CALLBACK testNtQueryInformationProcess(LPSTR, LONG_PTR)
{

    HMODULE  hDll = LoadLibraryW(L"Ntdll.dll");
    constexpr char func[] = { "NtQueryInformationProcess" };
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hDll, func);
    testNtPort(NtQueryInformationProcess);
    testCloseHandle(NtQueryInformationProcess);
    testFlag(NtQueryInformationProcess);
    return 0;
}

void testNtPort(_NtQueryInformationProcess NtQueryInformationProcess)
{
    __asm {
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    DWORD p;
    _asm
    {
        call l1
        l1 :
        pop eax
            mov p, eax
            call f1
            _EMIT 0xEA
            jmp l2
            f1 :
        pop ebx
            inc ebx
            push ebx
            mov eax, 0x11111111
            ret
            l2 :
        call f2
            mov ebx, 0x33333333
            jmp e
            f2 :
        mov ebx, 0x11111111
            pop ebx
            mov ebx, offset e
            push ebx
            ret
            e :
        mov ebx, 0x22222222
    }
    HANDLE hProcess = GetCurrentProcess();
    DWORD DebugPort;
    NtQueryInformationProcess(hProcess, 7, &DebugPort, sizeof(DWORD), NULL);


    g_keyptrIndex = 14;
    if (DebugPort != 0)
    {

    }
    else
    {

        keyAddress[g_keyptrIndex] = 'I';
    }

}
void testCloseHandle(_NtQueryInformationProcess NtQueryInformationProcess)
{
    __asm {
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    DWORD p;
    _asm
    {
        call l1
        l1 :
        pop eax
            mov p, eax
            call f1
            _EMIT 0xEA
            jmp l2
            f1 :
        pop ebx
            inc ebx
            push ebx
            mov eax, 0x11111111
            ret
            l2 :
        call f2
            mov ebx, 0x33333333
            jmp e
            f2 :
        mov ebx, 0x11111111
            pop ebx
            mov ebx, offset e
            push ebx
            ret
            e :
        mov ebx, 0x22222222
    }


    typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);

    // NtClose
    HMODULE h_ntdll = LoadLibraryW(L"Ntdll.dll");
    if (h_ntdll == NULL) {
      
        return;
    }
    g_keyptrIndex = 17;
    pNtClose NtClose = (pNtClose)GetProcAddress(h_ntdll, "NtClose");
    if (NtClose == NULL) {
        return;
    }

    __try {
        NtClose(reinterpret_cast<HANDLE>(0x99999999));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
       
        keyAddress[g_keyptrIndex] = 'o';
    }


    //keyAddress[g_keyptrIndex] = 'o';

}
void testFlag(_NtQueryInformationProcess NtQueryInformationProcess)
{
    __asm {
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    DWORD p;
    _asm
    {
        call l1
        l1 :
        pop eax
            mov p, eax
            call f1
            _EMIT 0xEA
            jmp l2
            f1 :
        pop ebx
            inc ebx
            push ebx
            mov eax, 0x11111111
            ret
            l2 :
        call f2
            mov ebx, 0x33333333
            jmp e
            f2 :
        mov ebx, 0x11111111
            pop ebx
            mov ebx, offset e
            push ebx
            ret
            e :
        mov ebx, 0x22222222
    }

    HANDLE hProcess = GetCurrentProcess();
    BOOL Flags;
    NtQueryInformationProcess(hProcess, 31, &Flags, sizeof(Flags), NULL);

    g_keyptrIndex = 18;
    if (Flags != 1)
    {
       
    }
    else
    {
        keyAddress[g_keyptrIndex] = 'o';
       
    }
   
}



char* FindKeyAddress()
{
    char* MoudleHeader = 0;
    MoudleHeader = (char*)GetModuleHandleA(NULL);
    for (size_t i = 0; i < 0x10000; i++)
    {
        DWORD temp = *(DWORD*)(MoudleHeader + i);
        if (temp == 0x12345678)
        {
            if (MoudleHeader[i+4]!=0x75)
            {
                keyAddress = (char*)((MoudleHeader + i+4));
                break;
            }
           
        }
    }

    return keyAddress;
}


int DebugFlag= testNtGlobalFlag();

int main()
{
    printf("He said that if all the key modifications involved in anti-debugging are identified, the flag can be retrieved.\n");
    __asm {
        _emit 075h
        _emit 2h
        _emit 0E9h
        _emit 0EDh
    }
    DWORD p;
    _asm
    {
        call l1
        l1 :
        pop eax
            mov p, eax
            call f1
            _EMIT 0xEA
            jmp l2
            f1 :
        pop ebx
            inc ebx
            push ebx
            mov eax, 0x11111111
            ret
            l2 :
        call f2
            mov ebx, 0x33333333
            jmp e
            f2 :
        mov ebx, 0x11111111
            pop ebx
            mov ebx, offset e
            push ebx
            ret
            e :
        mov ebx, 0x22222222
    }
    p = KeyFlah.AddressFlag;
   
    
    int ret= EnumUILanguagesA(testNtQueryInformationProcess,NULL,NULL);

    char* keybuffer2= keyAddress;
    unsigned char keybuffer3[]{
0x0f, 0x1a, 0x8a, 0x5a, 0x22, 0xab, 0x1e, 0x63, 0x19, 0x5a, 0x87, 0xf2, 0xe6, 0xf0, 0xd7, 0xde,
0xbf, 0xbb, 0xef, 0x04, 0x07, 0x89, 0x40, 0xd1, 0xcc, 0x2f, 0x78, 0xe2, 0x24, 0xf2, 0x62, 0xbc,
0x95, 0x58, 0x62, 0xb0, 0xdf, 0xd8, 0xbb, 0x6d, 0x21, 0x1e, 0xfe, 0xf0, 0xc4, 0xb3, 0xab, 0x7b,
0x29, 0xbc, 0x1f, 0xfe, 0x8a, 0x79, 0x26, 0xda, 0x08, 0x01, 0x85, 0x00, 0x7d, 0xbb, 0xee, 0x0f,
0x89, 0x59, 0xd4, 0x5f, 0xac, 0x18, 0xae, 0x0b, 0x4e, 0xf0, 0xb7, 0x05, 0x5c, 0x81, 0x04, 0x9f,
0xa4, 0x1c, 0x5d, 0xa0, 0xb9, 0x07, 0x92, 0x5c, 0x8a, 0x53, 0xf3, 0xff, 0xf7, 0xa7, 0xdd, 0x2e,
0xe6, 0xed, 0x0f, 0x77, 0x2c, 0x4a, 0x22, 0xf1, 0x36, 0x4f, 0xa7, 0xee, 0x0d, 0xd6, 0x04, 0x73,
0x55, 0x5e, 0x3e, 0x93, 0xa4, 0x34, 0x29, 0x67, 0xfc, 0x23, 0x79, 0x19, 0xd8, 0xc9, 0x2b, 0xcf };


    _RC4_CONTEXT rc4;
    rc4_init(&rc4, (unsigned char *)keybuffer2, 128);
    rc4_crypt(&rc4, keybuffer3, 128);
    printf("your flag is %s", keybuffer3);
    
}

```







testNtPort
testCloseHandle
testFlag
testBeginDebugged
testNtGlobalFlag

上面几个函数都是反调试检测，如果没用检测到调试就会把RC4算法的密钥还原，其中testCloseHandle函数逻辑有点特殊，他是检测到了才会还原





 密钥为 “flag:{ThisflagIsGoods}”。

之后通过rc4_crypt函数输出真正flag。 





```c++
RCTF{AntiDbg_Reversing_2025_v2.0_Ch4llenge}
```

