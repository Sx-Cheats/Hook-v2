#define ASMJIT_STATIC

#include "Hook.h"


void WriteWordChar(BYTE* base, BYTE* text)
{
    int idx = 0;
    DWORD OldProtect;
    do
    {

        OldProtect = NTapi::SetPageAccess((void*)(base + idx), PAGE_READWRITE);
        *(base + idx) = *(text + idx);
        NTapi::SetPageAccess((void*)(base + idx), OldProtect);
        idx++;

    } while (*(text + idx));
    OldProtect = NTapi::SetPageAccess((void*)(base + idx), PAGE_READWRITE);
    *(base + idx) = 0;
    NTapi::SetPageAccess((void*)(base + idx), OldProtect);
}

void __fastcall   ffghfgf(Hook_t* myhook, PRegisters registers)
{
    std::cout << " Hook Name : " << myhook->Name << std::endl;

    WriteWordChar((BYTE*)*(DWORD*)(registers->esp + 0x10), (BYTE*)"Hooked");

    myhook->Detach();

}


int main()
{
    auto HMessageBoxA = Hook((DWORD64)GetProcAddress(GetModuleHandleA("USER32.dll"), "MessageBoxA") + 0x5, (DWORD64)ffghfgf, 7, "Hook MessageBoxA");

    std::cout << "HMessageBoxA : 0x" << (PVOID)HMessageBoxA->BaseAddress << std::endl;

    MessageBoxA(NULL, " Hooked ", " I m Title ", MB_OK);

    MessageBoxA(NULL, " Not Hooked ", " Not Hook  ", MB_OK);

    system("pause > 0");

}
