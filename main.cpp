#include <cassert>
#include <cstdint>
#include <format>
#include <fstream>
#include <print>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#define NOMINMAX
#include <Windows.h>
#include <ddraw.h>

#pragma comment(lib, "ddraw")

std::vector<std::tuple<std::uint32_t, std::string>> ddcaps_map{
    {DDSCAPS_3DDEVICE, "DDSCAPS_3DDEVICE"},
    {DDSCAPS_ALLOCONLOAD, "DDSCAPS_ALLOCONLOAD"},
    {DDSCAPS_ALPHA, "DDSCAPS_ALPHA"},
    {DDSCAPS_BACKBUFFER, "DDSCAPS_BACKBUFFER"},
    {DDSCAPS_COMPLEX, "DDSCAPS_COMPLEX"},
    {DDSCAPS_FLIP, "DDSCAPS_FLIP"},
    {DDSCAPS_FRONTBUFFER, "DDSCAPS_FRONTBUFFER"},
    {DDSCAPS_HWCODEC, "DDSCAPS_HWCODEC"},
    {DDSCAPS_LIVEVIDEO, "DDSCAPS_LIVEVIDEO"},
    {DDSCAPS_LOCALVIDMEM, "DDSCAPS_LOCALVIDMEM"},
    {DDSCAPS_MIPMAP, "DDSCAPS_MIPMAP"},
    {DDSCAPS_MODEX, "DDSCAPS_MODEX"},
    {DDSCAPS_NONLOCALVIDMEM, "DDSCAPS_NONLOCALVIDMEM"},
    {DDSCAPS_OFFSCREENPLAIN, "DDSCAPS_OFFSCREENPLAIN"},
    {DDSCAPS_OVERLAY, "DDSCAPS_OVERLAY"},
    {DDSCAPS_OPTIMIZED, "DDSCAPS_OPTIMIZED"},
    {DDSCAPS_OWNDC, "DDSCAPS_OWNDC"},
    {DDSCAPS_PALETTE, "DDSCAPS_PALETTE"},
    {DDSCAPS_PRIMARYSURFACE, "DDSCAPS_PRIMARYSURFACE"},
    {DDSCAPS_PRIMARYSURFACELEFT, "DDSCAPS_PRIMARYSURFACELEFT"},
    {DDSCAPS_STANDARDVGAMODE, "DDSCAPS_STANDARDVGAMODE"},
    {DDSCAPS_SYSTEMMEMORY, "DDSCAPS_SYSTEMMEMORY"},
    {DDSCAPS_TEXTURE, "DDSCAPS_TEXTURE"},
    {DDSCAPS_VIDEOMEMORY, "DDSCAPS_VIDEOMEMORY"},
    {DDSCAPS_VIDEOPORT, "DDSCAPS_VIDEOPORT"},
    {DDSCAPS_VISIBLE, "DDSCAPS_VISIBLE"},
    {DDSCAPS_WRITEONLY, "DDSCAPS_WRITEONLY"},
    {DDSCAPS_ZBUFFER, "DDSCAPS_ZBUFFER"}};

std::ofstream g_log{};
LPDIRECTDRAW g_ddraw{};
HWND g_window{};
LPDIRECTDRAWSURFACE7 g_primary_surface{};
LPDIRECTDRAWSURFACE7 g_secondary_surface{};
std::unordered_map<std::string, std::uintptr_t> g_ddraw_hooks{};
std::unordered_map<std::string, std::uintptr_t> g_surface_hooks{};

template <class... Args>
void log(std::string_view msg, Args &&...args)
{
    g_log << std::vformat(msg, std::make_format_args(args...)) << std::endl;
}

std::string ddcaps_to_string(std::uint32_t ddcaps)
{
    return ddcaps_map |                                                                      //
           std::views::filter([ddcaps](const auto &e) { return ddcaps & std::get<0>(e); }) | //
           std::views::transform([](const auto &e) { return std::get<1>(e); }) |             //
           std::views::join_with('|') |                                                      //
           std::ranges::to<std::string>();
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

    g_window = CreateWindowExA(
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

    return g_window;
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
    log("\tskipping");

    return DD_OK;
    // return reinterpret_cast<HRESULT(__stdcall *)(void *, DWORD, DWORD, DWORD)>(
    //     g_ddraw_hooks["SetDisplayMode"])(that, unnamedParam1, unnamedParam2, unnamedParam3);
}

__declspec(dllexport) HRESULT __stdcall GetAttachedSurface_hook(
    void *that,
    LPDDSCAPS2 unnamedParam1,
    LPDIRECTDRAWSURFACE7 *unnamedParam2)
{
    log("GetAttachedSurface {} {} {}",
        reinterpret_cast<void *>(unnamedParam1),
        ddcaps_to_string(unnamedParam1->dwCaps),
        reinterpret_cast<void *>(unnamedParam2));

    *unnamedParam2 = g_secondary_surface;
    return DD_OK;

    // return reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSCAPS2, LPDIRECTDRAWSURFACE7 *)>(
    //     g_surface_hooks["GetAttachedSurface"])(that, unnamedParam1, unnamedParam2);
}

__declspec(dllexport) HRESULT __stdcall Blt_hook(
    void *that,
    LPRECT unnamedParam1,
    LPDIRECTDRAWSURFACE7 unnamedParam2,
    LPRECT unnamedParam3,
    DWORD unnamedParam4,
    LPDDBLTFX unnamedParam5)
{
    log("Blt {} {} {} {} {} {}",
        reinterpret_cast<void *>(that),
        reinterpret_cast<void *>(unnamedParam1),
        reinterpret_cast<void *>(unnamedParam2),
        reinterpret_cast<void *>(unnamedParam3),
        unnamedParam4,
        reinterpret_cast<void *>(unnamedParam5));

    const auto res =
        reinterpret_cast<HRESULT(__stdcall *)(void *, LPRECT, LPDIRECTDRAWSURFACE7, LPRECT, DWORD, LPDDBLTFX)>(
            g_surface_hooks["Blt"])(that, unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4, unnamedParam5);

    log("\tBlt returned {}", res);
    return res;
}

__declspec(dllexport) HRESULT __stdcall BltBatch_hook(
    void *that,
    LPDDBLTBATCH unnamedParam1,
    DWORD unnamedParam2,
    DWORD unnamedParam3)
{
    log("BltBatch {} {} {} {}",
        reinterpret_cast<void *>(that),
        reinterpret_cast<void *>(unnamedParam1),
        unnamedParam2,
        unnamedParam3);

    return reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDBLTBATCH, DWORD, DWORD)>(
        g_surface_hooks["BltBatch"])(that, unnamedParam1, unnamedParam2, unnamedParam3);
}

__declspec(dllexport) HRESULT __stdcall BltFast_hook(
    void *that,
    DWORD unnamedParam1,
    DWORD unnamedParam2,
    LPDIRECTDRAWSURFACE7 unnamedParam3,
    LPRECT unnamedParam4,
    DWORD unnamedParam5)
{
    log("BltFast {} {} {} {} {} {}",
        reinterpret_cast<void *>(that),
        unnamedParam1,
        unnamedParam2,
        reinterpret_cast<void *>(unnamedParam3),
        reinterpret_cast<void *>(unnamedParam4),
        unnamedParam5);

    return reinterpret_cast<HRESULT(__stdcall *)(void *, DWORD, DWORD, LPDIRECTDRAWSURFACE7, LPRECT, DWORD)>(
        g_surface_hooks["BltFast"])(that, unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4, unnamedParam5);
}

__declspec(dllexport) HRESULT __stdcall Flip_hook(void *that, LPDIRECTDRAWSURFACE7 unnamedParam1, DWORD unnamedParam2)
{
    log("Flip {} {} {}", that, reinterpret_cast<void *>(unnamedParam1), unnamedParam2);

    return reinterpret_cast<HRESULT(__stdcall *)(void *, LPDIRECTDRAWSURFACE7, DWORD)>(
        g_ddraw_hooks["Flip"])(that, unnamedParam1, unnamedParam2);
}

__declspec(dllexport) HRESULT __stdcall CreateSurface_hook(
    void *that,
    LPDDSURFACEDESC2 unnamedParam1,
    LPDIRECTDRAWSURFACE7 *unnamedParam2,
    IUnknown *unnamedParam3)
{
    log("CreateSurface {} {} {} {}",
        that,
        reinterpret_cast<void *>(unnamedParam1),
        reinterpret_cast<void *>(unnamedParam2),
        reinterpret_cast<void *>(unnamedParam3));

    log("DDSURFACEDESC2: {} {} {} {} {}",
        unnamedParam1->dwSize,
        unnamedParam1->dwWidth,
        unnamedParam1->dwHeight,
        unnamedParam1->dwFlags,
        ddcaps_to_string(unnamedParam1->ddsCaps.dwCaps));

    static int count{};
    assert(count++ < 2);

    if (unnamedParam1->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE)
    {
        auto new_unnamed_param1 = *unnamedParam1;
        new_unnamed_param1.dwFlags = DDSD_CAPS;
        new_unnamed_param1.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;

        log("new DDSURFACEDESC2: {} {} {} {}",
            new_unnamed_param1.dwWidth,
            new_unnamed_param1.dwHeight,
            new_unnamed_param1.dwFlags,
            ddcaps_to_string(new_unnamed_param1.ddsCaps.dwCaps));

        const auto res =
            reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 *, IUnknown *)>(
                g_ddraw_hooks["CreateSurface"])(that, &new_unnamed_param1, unnamedParam2, unnamedParam3);

        g_primary_surface = *unnamedParam2;

        LPDIRECTDRAWCLIPPER clipper{};
        g_ddraw->CreateClipper(0, &clipper, nullptr);
        clipper->SetHWnd(0, g_window);
        g_primary_surface->SetClipper(clipper);

        const auto original_get_attached_surface = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x30,
            reinterpret_cast<std::uintptr_t>(GetAttachedSurface_hook));
        g_surface_hooks["GetAttachedSurface"] = original_get_attached_surface;

        const auto original_blt = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x14,
            reinterpret_cast<std::uintptr_t>(Blt_hook));
        g_surface_hooks["Blt"] = original_blt;

        const auto original_blt_batch = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x18,
            reinterpret_cast<std::uintptr_t>(BltBatch_hook));
        g_surface_hooks["BltBatch"] = original_blt_batch;

        const auto original_blt_fast = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x1c,
            reinterpret_cast<std::uintptr_t>(BltFast_hook));
        g_surface_hooks["BltFast"] = original_blt_fast;

        const auto original_flip = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x2c,
            reinterpret_cast<std::uintptr_t>(Flip_hook));
        g_ddraw_hooks["Flip"] = original_flip;

        log("PRIMARY SURFACE {}", reinterpret_cast<void *>(g_primary_surface));

        return res;
    }
    else
    {
        DDSURFACEDESC2 new_unnamed_param1{
            .dwSize = 0x6c,
            .dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT,
            .dwHeight = 480,
            .dwWidth = 640,
            .ddsCaps = {.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY}};

        log("new DDSURFACEDESC2: {} {} {} {}",
            new_unnamed_param1.dwWidth,
            new_unnamed_param1.dwHeight,
            new_unnamed_param1.dwFlags,
            ddcaps_to_string(new_unnamed_param1.ddsCaps.dwCaps));

        const auto res =
            reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 *, IUnknown *)>(
                g_ddraw_hooks["CreateSurface"])(that, &new_unnamed_param1, unnamedParam2, unnamedParam3);

        g_secondary_surface = *unnamedParam2;

        const auto original_get_attached_surface = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_secondary_surface)) + 0x30,
            reinterpret_cast<std::uintptr_t>(GetAttachedSurface_hook));

        const auto original_blt = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_secondary_surface)) + 0x14,
            reinterpret_cast<std::uintptr_t>(Blt_hook));

        const auto original_blt_batch = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_secondary_surface)) + 0x18,
            reinterpret_cast<std::uintptr_t>(BltBatch_hook));

        const auto original_blt_fast = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_secondary_surface)) + 0x1c,
            reinterpret_cast<std::uintptr_t>(BltFast_hook));

        const auto original_flip = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_secondary_surface)) + 0x2c,
            reinterpret_cast<std::uintptr_t>(Flip_hook));

        log("SECONDARY SURFACE {}", reinterpret_cast<void *>(g_secondary_surface));

        hook(0x004baf38, reinterpret_cast<std::uintptr_t>(g_secondary_surface));

        return res;
    }
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

    const auto original_create_surface = hook(
        reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_ddraw)) + 0x18,
        reinterpret_cast<std::uintptr_t>(CreateSurface_hook));
    g_ddraw_hooks["CreateSurface"] = original_create_surface;

    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DWORD old_protect{};
        assert(
            ::VirtualProtect(reinterpret_cast<void *>(0x004BE000), 0x0002F000, PAGE_EXECUTE_READWRITE, &old_protect) ==
            TRUE);

        g_log = std::ofstream{"log.txt", std::ios::app};
        assert(g_log);

        log("\nlibrary loaded");

        hook(0x419120, reinterpret_cast<std::uintptr_t>(CreateWindowExA_hook));
        hook(0x419000, reinterpret_cast<std::uintptr_t>(DirectDrawCreate_hook));
    }

    return TRUE;
}
