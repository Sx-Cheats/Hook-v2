#pragma once
#include "./NTapi.h"
#include "./asmjit/asmjit.h"

#include <list>
#include <mutex>

using namespace asmjit;

#ifndef MaxHook
#define MaxHook 32
#endif

std::mutex hmutex;

#ifdef _WIN64
#pragma comment(lib,".//asmjit//asmjitx64.lib")

typedef struct Registers_t
{
    DEFAULT_SIZE r15;
    DEFAULT_SIZE r14;
    DEFAULT_SIZE r13;
    DEFAULT_SIZE r12;
    DEFAULT_SIZE r11;
    DEFAULT_SIZE r10;
    DEFAULT_SIZE r9;
    DEFAULT_SIZE r8;
    DEFAULT_SIZE rsi;
    DEFAULT_SIZE rbp;
    DEFAULT_SIZE rbx;
    DEFAULT_SIZE rdx;
    DEFAULT_SIZE rcx;
    DEFAULT_SIZE rax;
    DEFAULT_SIZE processor_flag;
    DEFAULT_SIZE rsp;
    DEFAULT_SIZE rdi;
    

} Registers, * PRegisters;

#elif _WIN32

#pragma comment(lib,".//asmjit//asmjitx32.lib")

typedef struct Registers_t
{
    DEFAULT_SIZE edi;
    DEFAULT_SIZE esi;
    DEFAULT_SIZE ebp;
    DEFAULT_SIZE ebx;
    DEFAULT_SIZE edx;
    DEFAULT_SIZE ecx;
    DEFAULT_SIZE eax;
    DEFAULT_SIZE processor_flag;
    DEFAULT_SIZE esp;

} Registers, * PRegisters;

#endif

typedef struct Hook_t
{
public:

    void  Detach();
    void  Attach();
    void  LockTunnelRegion();
    void  UnLockTunnelRegion();
    void  Destroy();
    void  SetHookFunction(PVOID func);
    void  SetName(const char* name);

    PBYTE Src = nullptr;
    PBYTE BaseAddress = nullptr;
    WORD NByteSteal;
    WORD Size = 0;

    WORD OpOrigin;
    WORD OpJmpToHF;

    PVOID HFunction;
    bool IsAttached = true;
    char Name[24];

    Hook_t() {};
    Hook_t(const char* name, bool isattached, PVOID hfunction, PBYTE src, PBYTE baseaddress, DWORD32 nbytesteal, WORD size, WORD oporigin, WORD OpJmpToHF) :IsAttached(isattached), HFunction(hfunction), Src(src), BaseAddress(baseaddress), NByteSteal(nbytesteal), Size(size), OpOrigin(oporigin), OpJmpToHF(OpJmpToHF) { strcpy(Name, name); };

};

struct HookStore_t : public x86::Assembler
{

public:

    JitRuntime rt;
    CodeHolder code;
    PBYTE BaseAddress;
    WORD  StackSize = 0;

    std::list<Hook_t*> Store;

    HookStore_t() : x86::Assembler(&code)
    {
        size_t stack_max_size = (MaxHook * 128);
        NtAllocateVirtualMemory(NtCurrentProcess(), (PVOID*)&BaseAddress, 0, (PSIZE_T)&stack_max_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        NTapi::Init();
    };

    PBYTE  Position()
    {
        return (BaseAddress + StackSize);
    }

    void DetachAllHooks()
    {
        for (auto i = Store.begin(); i != Store.end(); i++)
            (*i)->Detach();
    }

    Hook_t* GetHookByName(const char* Name)
    {
        for (auto i = Store.begin(); i != Store.end(); i++)
            if (!strcmp((*i)->Name, Name))
                return *i;

        return nullptr;
    }

    void AttachAllHooks()
    {
        for (auto i = Store.begin(); i != Store.end(); i++)
            (*i)->Attach();
    }

    void  DestroyHookByName(const char* Name)
    {
        for (auto i = Store.begin(); i != Store.end(); i++)
            if (!strcmp((*i)->Name, Name))
                (*i)->Destroy();
    }

    void JitClear(DEFAULT_SIZE BaseAddress = 0)
    {
        if (!BaseAddress)
            BaseAddress = (DEFAULT_SIZE)this->BaseAddress;

        code.detach(this);
        code.reset();
        code.init(rt.environment(), rt.cpuFeatures(), BaseAddress);
        code.attach(this);
    }

} HookStore;

void Hook_t::LockTunnelRegion()
{
    NTapi::SetPageAccess((void*)BaseAddress, PAGE_NOACCESS);
}

void Hook_t::UnLockTunnelRegion()
{
    NTapi::SetPageAccess((void*)BaseAddress, PAGE_EXECUTE_READ);
}

void Hook_t::SetHookFunction(PVOID func)
{
    bool b=hmutex.try_lock();

    DWORD OldProtect = NTapi::SetPageAccess(BaseAddress, PAGE_EXECUTE_READWRITE);
    
#ifdef _WIN64
    HookStore.JitClear();
    HookStore.mov(x86::rax, (DEFAULT_SIZE)func);
    HookStore.call(x86::rax);
#elif _WIN32
    HookStore.JitClear((DEFAULT_SIZE)(BaseAddress+OpJmpToHF));
    HookStore.call((DEFAULT_SIZE)func);
#endif

    HookStore.code.copySectionData((BaseAddress + OpJmpToHF), HookStore.code.codeSize(), 0);

    NTapi::SetPageAccess(BaseAddress, OldProtect);

    if (b)
        hmutex.unlock();


}

void Hook_t::SetName(const char* name)
{
   strcpy(Name, name);
}

void Hook_t::Detach()
{
    bool b = hmutex.try_lock();

    NTapi::NtMemCpy(Src, (BaseAddress+OpOrigin), NByteSteal);

    IsAttached = false;

    if (b)
        hmutex.unlock();

}

void Hook_t::Attach()
{
    bool b = hmutex.try_lock();

    DWORD32 OldProtect = NTapi::SetPageAccess((void*)Src, PAGE_EXECUTE_READWRITE);

#ifdef _WIN64
    HookStore.JitClear();
    HookStore.push(x86::rdi);
    HookStore.mov(x86::rdi, (DWORD64)BaseAddress);
    HookStore.jmp(x86::rdi);
    NTapi::NtZeroMemory((PBYTE)Src, NByteSteal, 0x90);
    HookStore.code.copySectionData(Src, HookStore.code.codeSize(), 0);
#elif _WIN32
    HookStore.JitClear((DWORD32)Src);
    HookStore.jmp(BaseAddress);
    NTapi::NtZeroMemory((PBYTE)Src, NByteSteal, 0x90);
    HookStore.code.copySectionData(Src, HookStore.code.codeSize(), 0);
#endif

    NTapi::SetPageAccess((void*)Src, OldProtect);
    IsAttached = true;

    if (b)
        hmutex.unlock();
}

void Hook_t::Destroy()
{
    bool b = hmutex.try_lock();

    Detach();

    PBYTE StackSize = (HookStore.BaseAddress + HookStore.StackSize);

    WORD cpy_block_hook_size = static_cast<WORD>(StackSize - (BaseAddress + Size));

    if (cpy_block_hook_size == 0)
        NTapi::NtZeroMemory(BaseAddress, Size);
    else
    {
        NTapi::NtMemCpy(BaseAddress, (BaseAddress + Size), cpy_block_hook_size);
        WORD c = static_cast<WORD>(StackSize - (BaseAddress + cpy_block_hook_size));
        NTapi::NtZeroMemory(BaseAddress + cpy_block_hook_size, c);
    }

    HookStore.StackSize -= Size;
    std::list<Hook_t*>::iterator chi = std::find(HookStore.Store.begin(), HookStore.Store.end(), this);
    if(chi != HookStore.Store.end())
          HookStore.Store.erase(chi);

    if (cpy_block_hook_size != 0)
    {
        PBYTE _bo = HookStore.BaseAddress;
        for (std::list<Hook_t*>::iterator h = chi++; h != HookStore.Store.end(); h++)
        {
            (*h)->Detach();
            (*h)->BaseAddress = _bo;
            (*h)->SetHookFunction((*h)->HFunction);
            (*h)->Attach();
            _bo = (HookStore.BaseAddress + (*h)->Size);

        }
    }

    Size = 0;
    BaseAddress = nullptr;
    OpJmpToHF = 0;
    OpOrigin = 0;

    if (b)
        hmutex.unlock();


}

#ifdef _WIN64

Hook_t* WINAPI Hook(DEFAULT_SIZE h_src, DEFAULT_SIZE h_dest, BYTE NByteSteal, const char* Name = "Hook", bool AutoAttach = true)
{
    bool b = hmutex.try_lock();

    if (HookStore.StackSize >= (MaxHook * 128))
        return nullptr;

    PBYTE HBaseAddress = HookStore.Position();
    NTapi::SetPageAccess((void*)HookStore.BaseAddress, PAGE_EXECUTE_READWRITE);

    Hook_t* h = new Hook_t();

    HookStore.JitClear((DEFAULT_SIZE)HBaseAddress);

    HookStore.lea(x86::rdi, x86::ptr(x86::rsp,8));
    HookStore.push(x86::rdi);

    HookStore.pushfq();

    HookStore.push(x86::rax);
    HookStore.push(x86::rcx);
    HookStore.push(x86::rdx);
    HookStore.push(x86::rbx);
    HookStore.push(x86::rbp);
    HookStore.push(x86::rsi);
    HookStore.push(x86::r8);
    HookStore.push(x86::r9);
    HookStore.push(x86::r10);
    HookStore.push(x86::r11);
    HookStore.push(x86::r12);
    HookStore.push(x86::r13);
    HookStore.push(x86::r14);
    HookStore.push(x86::r15);
    HookStore.mov(x86::rbp, x86::rsp);

    HookStore.mov(x86::rcx, h);     // 1 Arg
    HookStore.lea(x86::rdx, x86::ptr(x86::rsp));   //  2 Arg

    BYTE ojmp = HookStore.offset();

    HookStore.mov(x86::rax, h_dest);
    HookStore.call(x86::rax);

    HookStore.mov(x86::rsp, x86::rbp);

    HookStore.pop(x86::r15);
    HookStore.pop(x86::r14);
    HookStore.pop(x86::r13);
    HookStore.pop(x86::r12);
    HookStore.pop(x86::r11);
    HookStore.pop(x86::r10);
    HookStore.pop(x86::r9);
    HookStore.pop(x86::r8);
    HookStore.pop(x86::rsi);
    HookStore.pop(x86::rbp);
    HookStore.pop(x86::rbx);
    HookStore.pop(x86::rdx);
    HookStore.pop(x86::rcx);
    HookStore.pop(x86::rax);
    HookStore.popfq();
    HookStore.pop(x86::rsp);
    HookStore.sub(x86::rsp, 8);
    HookStore.pop(x86::rdi);

    BYTE op_origin = HookStore.offset();
    HookStore.embed((BYTE*)h_src, NByteSteal);
    HookStore.push(x86::rax);
    HookStore.push(x86::rax);
    HookStore.mov(x86::rax, (h_src + NByteSteal));
    HookStore.mov(x86::ptr(x86::rsp, 8), x86::rax);
    HookStore.pop(x86::rax);
    HookStore.ret();

    WORD code_size = static_cast<WORD>(HookStore.code.codeSize());

    HookStore.code.copySectionData(HBaseAddress, HookStore.code.codeSize(), 0);


    NTapi::SetPageAccess((void*)HookStore.BaseAddress, PAGE_EXECUTE_READ);

    if (AutoAttach)
    {
        DWORD SrcOldProtect = NTapi::SetPageAccess((void*)h_src, PAGE_EXECUTE_READWRITE);
        NTapi::NtZeroMemory((PBYTE)h_src, NByteSteal, 0x90);
        HookStore.JitClear();
        HookStore.push(x86::rdi);
        HookStore.mov(x86::rdi, (DEFAULT_SIZE)HBaseAddress);
        HookStore.jmp(x86::rdi);

        HookStore.code.copySectionData((PVOID)h_src, HookStore.code.codeSize(), 0);

        NTapi::SetPageAccess((void*)h_src, SrcOldProtect);
    }

    h->SetName(Name);
    h->IsAttached   =  AutoAttach;
    h->Src          =  (PBYTE)h_src;
    h->BaseAddress  =  HBaseAddress;
    h->NByteSteal   =  NByteSteal;
    h->Size         =  code_size;
    h->OpOrigin     =  op_origin;
    h->OpJmpToHF    =  ojmp;

    HookStore.StackSize += code_size;

    HookStore.Store.push_back(h);

    if (b)
        hmutex.unlock();

    return h;
}

#elif _WIN32


Hook_t* WINAPI Hook(DEFAULT_SIZE h_src, DEFAULT_SIZE h_dest, BYTE NByteSteal, const char* Name = "Hook", bool AutoAttach = true)
{
    bool b = hmutex.try_lock();

    if (HookStore.StackSize >= (MaxHook * 128))
        return nullptr;

    PBYTE HBaseAddress = HookStore.Position();
    NTapi::SetPageAccess((void*)HookStore.BaseAddress, PAGE_EXECUTE_READWRITE);

    Hook_t* h = new Hook_t();

    HookStore.JitClear((DEFAULT_SIZE)HBaseAddress);

    HookStore.push(x86::esp);
    HookStore.pushfd();
    HookStore.push(x86::eax);
    HookStore.push(x86::ecx);
    HookStore.push(x86::edx);
    HookStore.push(x86::ebx);
    HookStore.push(x86::ebp);
    HookStore.push(x86::esi);
    HookStore.push(x86::edi);


    HookStore.mov(x86::ebp, x86::esp);

    HookStore.mov(x86::ecx, h);                          // 1 Arg
    HookStore.lea(x86::edx, x86::ptr(x86::esp));   //  2 Arg 

    BYTE ojmp = HookStore.offset();
    HookStore.call(h_dest);

    HookStore.mov(x86::esp, x86::ebp); 

    HookStore.pop(x86::edi);
    HookStore.pop(x86::esi);
    HookStore.pop(x86::ebp);
    HookStore.pop(x86::ebx);
    HookStore.pop(x86::edx);
    HookStore.pop(x86::ecx);
    HookStore.pop(x86::eax);
    HookStore.popfd();
    HookStore.pop(x86::esp);

    BYTE op_origin = HookStore.offset();
    HookStore.embed((BYTE*)h_src, NByteSteal);
    HookStore.push(h_src + NByteSteal);
    HookStore.ret();

    WORD code_size = static_cast<WORD>(HookStore.code.codeSize());

    HookStore.code.copySectionData(HBaseAddress, HookStore.code.codeSize(), 0);

    NTapi::SetPageAccess((void*)HookStore.BaseAddress, PAGE_EXECUTE_READ);

    if (AutoAttach)
    {
        DWORD SrcOldProtect = NTapi::SetPageAccess((void*)h_src, PAGE_EXECUTE_READWRITE);
        NTapi::NtZeroMemory((PBYTE)h_src, NByteSteal, 0x90);
        HookStore.JitClear(h_src);
        HookStore.jmp((DWORD32)HBaseAddress - 0);
        HookStore.code.relocEntries();
        HookStore.code.copySectionData((PVOID)h_src, HookStore.code.codeSize(), 0);

        NTapi::SetPageAccess((void*)h_src, SrcOldProtect);
    }


    h->SetName(Name);
    h->IsAttached = AutoAttach;
    h->Src = (PBYTE)h_src;
    h->BaseAddress = HBaseAddress;
    h->NByteSteal = NByteSteal;
    h->Size = code_size;
    h->OpOrigin =  op_origin;
    h->OpJmpToHF =   ojmp;
    h->HFunction = (PVOID)h_dest;

    HookStore.StackSize += code_size;
    HookStore.Store.push_back(h);

    if (b)
        hmutex.unlock();

    return h;
}

#endif