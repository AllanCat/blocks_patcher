#include <cassert>
#include <cstdint>
#include <format>
#include <fstream>
#include <print>
#include <string>
#include <string_view>
#include <unordered_map>

#define NOMINMAX
#include <Windows.h>
#include <ddraw.h>

#pragma comment(lib, "ddraw")

std::ofstream g_log{};
LPDIRECTDRAW g_ddraw{};
std::unordered_map<std::string, std::uintptr_t> g_ddraw_hooks{};

template <class... Args>
void log(std::string_view msg, Args &&...args)
{
    g_log << std::vformat(msg, std::make_format_args(args...)) << std::endl;
}

std::uintptr_t hook(std::uintptr_t iat_addr, std::uintptr_t hook_addr)
{
    // make iat_addr RW
    ::DWORD old_protect;
    assert(
        ::VirtualProtect(reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t), PAGE_READWRITE, &old_protect) ==
        TRUE);

    std::uintptr_t original_addr{};
    std::memcpy(&original_addr, reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t));

    // write hook_addr to iat_addr
    std::memcpy(reinterpret_cast<void *>(iat_addr), &hook_addr, sizeof(std::uintptr_t));

    // restore iat_addr's original protection
    assert(
        ::VirtualProtect(reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t), old_protect, &old_protect) ==
        TRUE);

    log("hooked address at {:#x} with {:#x} (original address {:#x})", iat_addr, hook_addr, original_addr);

    return original_addr;
}

__declspec(dllexport) HWND __stdcall CreateWindowExA_hook(
    DWORD dwExStyle,
    LPCSTR lpClassName,
    LPCSTR lpWindowName,
    DWORD dwStyle,
    int X,
    int Y,
    int nWidth,
    int nHeight,
    HWND hWndParent,
    HMENU hMenu,
    HINSTANCE hInstance,
    LPVOID lpParam)
{
    log("CreateWindowExA {} {} {} {} {} {} {} {} {} {} {} {}",
        dwExStyle,
        lpClassName,
        lpWindowName,
        dwStyle,
        X,
        Y,
        nWidth,
        nHeight,
        reinterpret_cast<void *>(hWndParent),
        reinterpret_cast<void *>(hMenu),
        reinterpret_cast<void *>(hInstance),
        lpParam);

    const auto new_width = 640;
    const auto new_height = 480;
    const auto new_style = dwStyle ^ WS_POPUP;

    log("CreateWindowExA_hook {} {} {} {} {} {} {} {} {} {} {} {}",
        dwExStyle,
        lpClassName,
        lpWindowName,
        new_style,
        X,
        Y,
        new_width,
        new_height,
        reinterpret_cast<void *>(hWndParent),
        reinterpret_cast<void *>(hMenu),
        reinterpret_cast<void *>(hInstance),
        lpParam);

    return CreateWindowExA(
        dwExStyle,
        lpClassName,
        lpWindowName,
        new_style,
        X,
        Y,
        new_width,
        new_height,
        hWndParent,
        hMenu,
        hInstance,
        lpParam);
}

__declspec(dllexport) HRESULT __stdcall SetCooperativeLevel_hook(void *that, HWND unnamedParam1, DWORD unnamedParam2)
{
    log("SetCooperativeLevel {} {} {}",
        that,
        reinterpret_cast<void *>(unnamedParam1),
        reinterpret_cast<void *>(unnamedParam2));

    const auto new_unnamed_param2 = DDSCL_NORMAL;

    log("SetCooperativeLevel_hook {} {} {}",
        that,
        reinterpret_cast<void *>(unnamedParam1),
        reinterpret_cast<void *>(new_unnamed_param2));

    return reinterpret_cast<HRESULT(__stdcall *)(void *, HWND, DWORD)>(
        g_ddraw_hooks["SetCooperativeLevel"])(that, unnamedParam1, new_unnamed_param2);
}

__declspec(dllexport) HRESULT __stdcall SetDisplayMode_hook(
    void *that,
    DWORD unnamedParam1,
    DWORD unnamedParam2,
    DWORD unnamedParam3)
{
    log("SetDisplayMode {} {} {} {}", that, unnamedParam1, unnamedParam2, unnamedParam3);

    return reinterpret_cast<HRESULT(__stdcall *)(void *, DWORD, DWORD, DWORD)>(
        g_ddraw_hooks["SetDisplayMode"])(that, unnamedParam1, unnamedParam2, unnamedParam3);
}

__declspec(dllexport) HRESULT __stdcall DirectDrawCreate_hook(GUID *lpGUID, LPDIRECTDRAW *lplpDD, IUnknown *pUnkOuter)
{
    log("DirectDrawCreate {} {} {}",
        reinterpret_cast<void *>(lpGUID),
        reinterpret_cast<void *>(lplpDD),
        reinterpret_cast<void *>(pUnkOuter));

    const auto result = ::DirectDrawCreate(lpGUID, lplpDD, pUnkOuter);

    g_ddraw = *lplpDD;
    log("DIRECTDRAW {} vtable: {}", reinterpret_cast<void *>(g_ddraw), *reinterpret_cast<void **>(g_ddraw));

    const auto original_set_cooperative_level = hook(
        reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_ddraw)) + 0x50,
        reinterpret_cast<std::uintptr_t>(SetCooperativeLevel_hook));
    g_ddraw_hooks["SetCooperativeLevel"] = original_set_cooperative_level;

    const auto original_set_display_mode = hook(
        reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_ddraw)) + 0x54,
        reinterpret_cast<std::uintptr_t>(SetDisplayMode_hook));
    g_ddraw_hooks["SetDisplayMode"] = original_set_display_mode;

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_log = std::ofstream{"log.txt", std::ios::app};
        assert(g_log);

        log("\nlibrary loaded");

        hook(0x419120, reinterpret_cast<std::uintptr_t>(CreateWindowExA_hook));
        hook(0x419000, reinterpret_cast<std::uintptr_t>(DirectDrawCreate_hook));
    }

    return TRUE;
}
