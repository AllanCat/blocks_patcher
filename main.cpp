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

std::vector<std::tuple<std::uint32_t, std::string>> fuload_map{
    {LR_CREATEDIBSECTION, "LR_CREATEDIBSECTION"},
    {LR_DEFAULTCOLOR, "LR_DEFAULTCOLOR"},
    {LR_DEFAULTSIZE, "LR_DEFAULTSIZE"},
    {LR_LOADFROMFILE, "LR_LOADFROMFILE"},
    {LR_LOADMAP3DCOLORS, "LR_LOADMAP3DCOLORS"},
    {LR_LOADTRANSPARENT, "LR_LOADTRANSPARENT"},
    {LR_MONOCHROME, "LR_MONOCHROME"},
    {LR_SHARED, "LR_SHARED"},
    {LR_VGACOLOR, "LR_VGACOLOR"}};

std::vector<std::tuple<std::uint32_t, std::string>> palette_caps_maps{
    {DDPCAPS_1BIT, "DDPCAPS_1BIT"},
    {DDPCAPS_2BIT, "DDPCAPS_2BIT"},
    {DDPCAPS_4BIT, "DDPCAPS_4BIT"},
    {DDPCAPS_8BIT, "DDPCAPS_8BIT"},
    {DDPCAPS_8BITENTRIES, "DDPCAPS_8BITENTRIES"},
    {DDPCAPS_ALPHA, "DDPCAPS_ALPHA"},
    {DDPCAPS_ALLOW256, "DDPCAPS_ALLOW256"},
    {DDPCAPS_PRIMARYSURFACE, "DDPCAPS_PRIMARYSURFACE"},
    {DDPCAPS_PRIMARYSURFACELEFT, "DDPCAPS_PRIMARYSURFACELEFT"},
    {DDPCAPS_VSYNC, "DDPCAPS_VSYNC"}};

std::ofstream g_log{};
LPDIRECTDRAW g_ddraw{};
HWND g_window{};
LPDIRECTDRAWSURFACE7 g_primary_surface{};
LPDIRECTDRAWSURFACE7 g_back_buffer_surface{};
LPDIRECTDRAWSURFACE7 g_image_surface{};
std::unordered_map<std::string, std::uintptr_t> g_ddraw_hooks{};
std::unordered_map<std::string, std::uintptr_t> g_surface_hooks{};
std::unordered_map<std::string, std::uintptr_t> g_palette_hooks{};

PALETTEENTRY g_palette[256]{};

std::uint32_t g_width = ::GetSystemMetrics(SM_CXSCREEN);
std::uint32_t g_height = ::GetSystemMetrics(SM_CYSCREEN);
std::vector<BYTE> g_image_pixels{};

// simple log function
template <class... Args>
void log(std::string_view msg, Args &&...args)
{
    // uncomment to log to file
    // g_log << std::vformat(msg, std::make_format_args(args...)) << std::endl;
}

std::string flags_to_string(const auto &map, std::uint32_t flag)
{
    return map |                                                                         //
           std::views::filter([flag](const auto &e) { return flag & std::get<0>(e); }) | //
           std::views::transform([](const auto &e) { return std::get<1>(e); }) |         //
           std::views::join_with('|') |                                                  //
           std::ranges::to<std::string>();
}

std::string ddcaps_to_string(std::uint32_t ddcaps)
{
    return flags_to_string(ddcaps_map, ddcaps);
}

std::string fuload_to_string(std::uint32_t fuload)
{
    return flags_to_string(fuload_map, fuload);
}

std::string palette_caps_to_string(std::uint32_t palette_caps)
{
    return flags_to_string(palette_caps_maps, palette_caps);
}

// patch out an address with another, useful for IAT hooking but can be abused for other patching needs
std::uintptr_t hook(std::uintptr_t iat_addr, std::uintptr_t hook_addr)
{
    log("hooking address at {:#x} with {:#x}", iat_addr, hook_addr);

    // make hook location writable
    ::DWORD old_protect;
    assert(
        ::VirtualProtect(reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t), PAGE_READWRITE, &old_protect) ==
        TRUE);

    // save off original address
    std::uintptr_t original_addr{};
    std::memcpy(&original_addr, reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t));

    // overwrite
    std::memcpy(reinterpret_cast<void *>(iat_addr), &hook_addr, sizeof(std::uintptr_t));

    // restore original protection
    assert(
        ::VirtualProtect(reinterpret_cast<void *>(iat_addr), sizeof(std::uintptr_t), old_protect, &old_protect) ==
        TRUE);

    log("hooked address at {:#x} with {:#x} (original address {:#x})", iat_addr, hook_addr, original_addr);

    return original_addr;
}

// anything named *_hook is a hook of a real function

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

    *unnamedParam2 = g_back_buffer_surface;
    return DD_OK;
}

__declspec(dllexport) HRESULT __stdcall SetEntries_hook(
    void *that,
    DWORD unnamedParam1,
    DWORD unnamedParam2,
    DWORD unnamedParam3,
    LPPALETTEENTRY unnamedParam4)
{
    log("SetEntries {} {} {} {} {}",
        reinterpret_cast<void *>(that),
        unnamedParam1,
        unnamedParam2,
        unnamedParam3,
        reinterpret_cast<void *>(unnamedParam4));

    // save off a copy of the palette entries
    std::memcpy(g_palette, unnamedParam4, sizeof(g_palette));

    for (const auto &entry : g_palette)
    {
        log("\t{} {} {} {}", entry.peRed, entry.peGreen, entry.peBlue, entry.peFlags);
    }

    const auto res = reinterpret_cast<HRESULT(__stdcall *)(void *, DWORD, DWORD, DWORD, LPPALETTEENTRY)>(
        g_palette_hooks["SetEntries"])(that, unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4);

    log("\tSetEntries returned {}", res);
    return res;
}

__declspec(dllexport) HRESULT __stdcall CreatePalette_hook(
    void *that,
    DWORD unnamedParam1,
    LPPALETTEENTRY unnamedParam2,
    LPDIRECTDRAWPALETTE *unnamedParam3,
    IUnknown *unnamedParam4)
{
    log("CreatePalette {} {} {} {} {}",
        reinterpret_cast<void *>(that),
        unnamedParam1,
        reinterpret_cast<void *>(unnamedParam2),
        reinterpret_cast<void *>(unnamedParam3),
        reinterpret_cast<void *>(unnamedParam4));

    const auto res =
        reinterpret_cast<HRESULT(__stdcall *)(void *, DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE *, IUnknown *)>(
            g_ddraw_hooks["CreatePalette"])(that, unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4);

    const auto original_set_entries = hook(
        reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(*unnamedParam3)) + 0x18,
        reinterpret_cast<std::uintptr_t>(SetEntries_hook));
    g_palette_hooks["SetEntries"] = original_set_entries;

    log("\tCreatePalette returned {}", res);
    return res;
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

    DDSURFACEDESC2 ddsd{};
    ddsd.dwSize = sizeof(ddsd);

    static auto once = false;

    //  manually apply palette (once) to the loaded image as palett's don't work as expected in windows mode

    if (!once)
    {
        once = true;
        assert(g_image_surface->Lock(nullptr, &ddsd, DDLOCK_WAIT, nullptr) == DD_OK);

        auto *pSurfaceMemory = static_cast<BYTE *>(ddsd.lpSurface);
        const auto pitch = ddsd.lPitch;

        log("pitch: {} width: {} height: {}", pitch, ddsd.dwWidth, ddsd.dwHeight);

        for (auto y = 0; y < ddsd.dwHeight; ++y)
        {
            for (auto x = 0; x < ddsd.dwWidth; ++x)
            {
                auto *pRow = pSurfaceMemory + ((y * ddsd.dwWidth) + x) * 4;
                auto paletteIndex = g_image_pixels[(ddsd.dwHeight - y - 1) * ddsd.dwWidth + x];

                log("palette index: {}", paletteIndex);

                auto colour = g_palette[paletteIndex];

                pRow[0] = colour.peBlue;
                pRow[1] = colour.peGreen;
                pRow[2] = colour.peRed;
                pRow[3] = 0;

                // for some reason the bitmap image has magenta instead of a white background - so fix that
                if (pRow[0] == 0xff && pRow[1] == 0 && pRow[2] == 0xff)
                {
                    pRow[1] = 0xff;
                }
            }
        }

        g_image_surface->Unlock(nullptr);
    }

    // Flip() would internally manage the buffers for us on full screen but not in windowed mode
    // simulate that by blitting the back buffer to the screen

    const auto res =
        reinterpret_cast<HRESULT(__stdcall *)(void *, LPRECT, LPDIRECTDRAWSURFACE7, LPRECT, DWORD, LPDDBLTFX)>(
            g_surface_hooks["Blt"])(that, nullptr, g_back_buffer_surface, nullptr, DDBLT_WAIT, nullptr);

    log("\tFlip(Blt) returned {}", res);

    return res;
}

__declspec(dllexport) HRESULT __stdcall Lock_hook(
    void *that,
    LPRECT unnamedParam1,
    LPDDSURFACEDESC2 unnamedParam2,
    DWORD unnamedParam3,
    HANDLE unnamedParam4)
{
    log("Lock {} {} {} {} {}",
        reinterpret_cast<void *>(that),
        reinterpret_cast<void *>(unnamedParam1),
        reinterpret_cast<void *>(unnamedParam2),
        unnamedParam3,
        reinterpret_cast<void *>(unnamedParam4));

    return reinterpret_cast<HRESULT(__stdcall *)(void *, LPRECT, LPDDSURFACEDESC2, DWORD, HANDLE)>(
        g_surface_hooks["Lock"])(that, unnamedParam1, unnamedParam2, unnamedParam3, unnamedParam4);
}

__declspec(dllexport) HRESULT __stdcall Unlock_hook(void *that, LPRECT unnamedParam1)
{
    log("Unlock {} {}", reinterpret_cast<void *>(that), reinterpret_cast<void *>(unnamedParam1));

    return reinterpret_cast<HRESULT(__stdcall *)(void *, LPRECT)>(g_surface_hooks["Unlock"])(that, unnamedParam1);
}

__declspec(dllexport) HRESULT __stdcall SetPalette_hook(void *that, LPDIRECTDRAWPALETTE unnamedParam1)
{
    log("SetPalette {} {}", that, reinterpret_cast<void *>(unnamedParam1));

    const auto res = reinterpret_cast<HRESULT(__stdcall *)(void *, LPDIRECTDRAWPALETTE)>(
        g_surface_hooks["SetPalette"])(that, unnamedParam1);

    log("\tSetPalette returned {}", res);
    return res;
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

    // this function is called twice, once to create a primary surface and once to create an image surface
    // the image surface is simple, the game simply copies the resource BITMAP to that which is a sprite map and then
    // blits part of that to the other buffer
    // the primary buffer assumes it's running in fullscreen and that flip will automatically handle the double
    // buffering when we make it windowed we need to create and manage two buffers ourselves

    // sanity check i understand how the code works
    static int count{};
    assert(count++ < 2);

    // if this is the call for the full screen buffer then create a normal primary buffer
    if (unnamedParam1->ddsCaps.dwCaps & DDSCAPS_PRIMARYSURFACE)
    {
        auto new_unnamed_param1 = *unnamedParam1;
        new_unnamed_param1.dwFlags = DDSD_CAPS;
        new_unnamed_param1.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
        new_unnamed_param1.dwWidth = g_width;
        new_unnamed_param1.dwHeight = g_height;

        log("new DDSURFACEDESC2: {} {} {} {}",
            new_unnamed_param1.dwWidth,
            new_unnamed_param1.dwHeight,
            new_unnamed_param1.dwFlags,
            ddcaps_to_string(new_unnamed_param1.ddsCaps.dwCaps));

        const auto res =
            reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 *, IUnknown *)>(
                g_ddraw_hooks["CreateSurface"])(that, &new_unnamed_param1, unnamedParam2, unnamedParam3);

        g_primary_surface = *unnamedParam2;

        // constrain rendering to window, otherwise it'll still write to the whole screen
        LPDIRECTDRAWCLIPPER clipper{};
        g_ddraw->CreateClipper(0, &clipper, nullptr);
        clipper->SetHWnd(0, g_window);
        g_primary_surface->SetClipper(clipper);

        // direct draw objects are COM objects, so the first thing on the returned pointer is a vtable pointer
        // this makes it easy to hook
        // we also save off the original functions

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
        g_surface_hooks["Flip"] = original_flip;

        const auto original_lock = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x64,
            reinterpret_cast<std::uintptr_t>(Lock_hook));
        g_surface_hooks["Lock"] = original_lock;

        const auto original_unlock = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x80,
            reinterpret_cast<std::uintptr_t>(Unlock_hook));
        g_surface_hooks["Unlock"] = original_unlock;

        const auto original_set_palette = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_primary_surface)) + 0x7c,
            reinterpret_cast<std::uintptr_t>(SetPalette_hook));
        g_surface_hooks["SetPalette"] = original_set_palette;

        log("PRIMARY SURFACE {}", reinterpret_cast<void *>(g_primary_surface));

        // also create a back buffer for double buffering
        {
            DDSURFACEDESC2 new_unnamed_param1{
                .dwSize = 0x6c,
                .dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT,
                .dwHeight = g_height,
                .dwWidth = g_width,
                .ddsCaps = {.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY}};

            log("new DDSURFACEDESC2: {} {} {} {}",
                new_unnamed_param1.dwWidth,
                new_unnamed_param1.dwHeight,
                new_unnamed_param1.dwFlags,
                ddcaps_to_string(new_unnamed_param1.ddsCaps.dwCaps));

            const auto res =
                reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 *, IUnknown *)>(
                    g_ddraw_hooks["CreateSurface"])(that, &new_unnamed_param1, unnamedParam2, unnamedParam3);

            g_back_buffer_surface = *unnamedParam2;

            // apply COM hooks

            const auto original_get_attached_surface = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x30,
                reinterpret_cast<std::uintptr_t>(GetAttachedSurface_hook));

            const auto original_blt = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x14,
                reinterpret_cast<std::uintptr_t>(Blt_hook));

            const auto original_blt_batch = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x18,
                reinterpret_cast<std::uintptr_t>(BltBatch_hook));

            const auto original_blt_fast = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x1c,
                reinterpret_cast<std::uintptr_t>(BltFast_hook));

            const auto original_flip = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x2c,
                reinterpret_cast<std::uintptr_t>(Flip_hook));

            const auto original_lock = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x64,
                reinterpret_cast<std::uintptr_t>(Lock_hook));

            const auto original_unlock = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x80,
                reinterpret_cast<std::uintptr_t>(Unlock_hook));

            const auto original_set_palette = hook(
                reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_back_buffer_surface)) + 0x7c,
                reinterpret_cast<std::uintptr_t>(SetPalette_hook));

            log("BACK BUFFER SURFACE {}", reinterpret_cast<void *>(g_back_buffer_surface));
        }

        *unnamedParam2 = g_primary_surface;

        return res;
    }
    else
    {
        // image buffer

        DDSURFACEDESC2 new_unnamed_param1{
            .dwSize = 0x6c,
            .dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT,
            .dwHeight = unnamedParam1->dwHeight,
            .dwWidth = unnamedParam1->dwWidth,
            .ddsCaps = {.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY}};

        log("new DDSURFACEDESC2: {} {} {} {}",
            new_unnamed_param1.dwWidth,
            new_unnamed_param1.dwHeight,
            new_unnamed_param1.dwFlags,
            ddcaps_to_string(new_unnamed_param1.ddsCaps.dwCaps));

        const auto res =
            reinterpret_cast<HRESULT(__stdcall *)(void *, LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE7 *, IUnknown *)>(
                g_ddraw_hooks["CreateSurface"])(that, &new_unnamed_param1, unnamedParam2, unnamedParam3);

        g_image_surface = *unnamedParam2;

        // apply COM hooks

        const auto original_get_attached_surface = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x30,
            reinterpret_cast<std::uintptr_t>(GetAttachedSurface_hook));

        const auto original_blt = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x14,
            reinterpret_cast<std::uintptr_t>(Blt_hook));

        const auto original_blt_batch = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x18,
            reinterpret_cast<std::uintptr_t>(BltBatch_hook));

        const auto original_blt_fast = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x1c,
            reinterpret_cast<std::uintptr_t>(BltFast_hook));

        const auto original_flip = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x2c,
            reinterpret_cast<std::uintptr_t>(Flip_hook));

        const auto original_lock = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x64,
            reinterpret_cast<std::uintptr_t>(Lock_hook));

        const auto original_unlock = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x80,
            reinterpret_cast<std::uintptr_t>(Unlock_hook));

        const auto original_set_palette = hook(
            reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_image_surface)) + 0x7c,
            reinterpret_cast<std::uintptr_t>(SetPalette_hook));

        log("IMAGE SURFACE {}", reinterpret_cast<void *>(g_image_surface));

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

    const auto original_create_palette = hook(
        reinterpret_cast<std::uintptr_t>(*reinterpret_cast<void **>(g_ddraw)) + 0x14,
        reinterpret_cast<std::uintptr_t>(CreatePalette_hook));
    g_ddraw_hooks["CreatePalette"] = original_create_palette;

    return result;
}

__declspec(dllexport) int __stdcall GetSystemMetrics_hook(int nIndex)
{
    log("GetSystemMetrics {} ", nIndex);

    switch (nIndex)
    {
        case SM_CXSCREEN: return g_width;
        case SM_CYSCREEN: return g_height;
        default: return GetSystemMetrics(nIndex);
    }
}

__declspec(dllexport) HANDLE __stdcall LoadImageA_hook(
    HINSTANCE hInst,
    LPCSTR name,
    UINT type,
    int cx,
    int cy,
    UINT fuLoad)
{
    log("LoadImageA {} {} {} {} {} {} ({:x})",
        reinterpret_cast<void *>(hInst),
        name,
        type,
        cx,
        cy,
        fuload_to_string(fuLoad),
        fuLoad);

    const auto res = (HBITMAP)LoadImage(hInst, name, IMAGE_BITMAP, cx, cy, fuLoad);
    HDC hdc = GetDC(nullptr);

    BITMAP bmp{};
    assert(GetObject((HBITMAP)res, sizeof(BITMAP), &bmp) != 0);

    int width = bmp.bmWidth;
    int height = bmp.bmHeight;
    int bitCount = bmp.bmBitsPixel;

    log("{} {} {} {} {} {} {} {} {}",
        reinterpret_cast<void *>(res),
        width,
        height,
        bitCount,
        bmp.bmPlanes,
        bmp.bmWidthBytes,
        bmp.bmType,
        bmp.bmHeight,
        bmp.bmWidth);

    int bytesPerPixel = bitCount / 8;
    int dataSize = width * height * bytesPerPixel;
    log("dataSize: {}", dataSize);

    // save off a copy of the original bitmap data so we can do a palette conversion later
    g_image_pixels.resize(dataSize * 10);
    std::memcpy(g_image_pixels.data(), bmp.bmBits, dataSize);

    return res;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        // for some reason the game tries to write to the resource section which is loaded as read only - so fix that
        DWORD old_protect{};
        assert(
            ::VirtualProtect(reinterpret_cast<void *>(0x004BE000), 0x0002F000, PAGE_EXECUTE_READWRITE, &old_protect) ==
            TRUE);

        g_log = std::ofstream{"log.txt", std::ios::app};
        assert(g_log);

        log("\nlibrary loaded");

        // hook various win32 functions
        hook(0x419120, reinterpret_cast<std::uintptr_t>(CreateWindowExA_hook));
        hook(0x419124, reinterpret_cast<std::uintptr_t>(GetSystemMetrics_hook));
        hook(0x419000, reinterpret_cast<std::uintptr_t>(DirectDrawCreate_hook));
        hook(0x41910C, reinterpret_cast<std::uintptr_t>(LoadImageA_hook));

        const auto user32_base = reinterpret_cast<std::uintptr_t>(::GetModuleHandleA("user32.dll"));
        log("user32.dll base: {:x}", user32_base);

        // deep in the bowels of LoadImageA it calls a function which compares the size of the internal image resource
        // for some reason that always fails, despite the image being legit
        // so patch out that function to just return (eax is non-zero so will pass follow on check)
        std::uintptr_t rets = 0xc3c3c3c3;
        hook(user32_base + 0x39eef, rets);
    }

    return TRUE;
}
