// dlc_license_plugin.cpp — UCOnline2 plugin (ABI v1)
// Hooks ISteamUser::UserHasLicenseForApp + GetEncryptedAppTicket so a
// Spacewar-spoofed session stays stable and Elden Ring DLC reads as owned.
// Build x64 Release -> dlc_license.dll, drop in the plugins folder.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

// ------------------------------------------------------------------
// If you have MinHook, define HAVE_MINHOOK and add the MinHook lib.
// Otherwise the manual trampoline hook below is used.
// ------------------------------------------------------------------
// #define HAVE_MINHOOK
// #include "MinHook.h"

#ifdef HAVE_MINHOOK
  #define HOOK_CREATE(t,p,f)  MH_CreateHook((LPVOID)(t), (LPVOID)(p), (LPVOID*)(f))
  #define HOOK_ENABLE(t)      MH_EnableHook((LPVOID)(t))
#else
  // ---- tiny manual x64 detour --------------------------------------
  struct Detour { void* target; void* hook; unsigned char orig[16]; bool on; };
  static Detour* g_detours[8]; static int g_detour_count = 0;

  static bool MakeDetour(void* target, void* hook, Detour* d) {
      d->target = target; d->hook = hook; d->on = false;
      memcpy(d->orig, target, 16);
      DWORD old;
      VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
      unsigned char* p = (unsigned char*)target;
      // mov rax, hook ; jmp rax ; nop...
      p[0] = 0x48; p[1] = 0xB8;
      *(void**)(p + 2) = hook;
      p[10] = 0xFF; p[11] = 0xE0;
      for (int i = 12; i < 16; ++i) p[i] = 0x90;
      VirtualProtect(target, 16, old, &old);
      d->on = true;
      return true;
  }
  #define HOOK_CREATE(t,p,f)  MakeDetour((LPVOID)(t),(LPVOID)(p), *(f))
  #define HOOK_ENABLE(t)      ((void)0)
#endif

// ------------------------------------------------------------------
// UCO v1 plugin ABI (as described in the repo readme).
// Field names *should* match; if the compiler complains, adjust the
// struct to your uco_plugin.h.
// ------------------------------------------------------------------
struct UCO_PluginContext {
    void* steamUser;       // ISteamUser*
    void* steamApps;       // ISteamApps*
    void* steamUserStats;  // ISteamUserStats*
    void* steamUtils;      // ISteamUtils*
    uint32_t appId;
    uint32_t ogAppId;
    void (*log)(const char*);
    bool (*registerPatcher)(void* target, void* hook, void** orig);
};

static UCO_PluginContext g_ctx{};
static void Log(const char* m) { if (g_ctx.log) g_ctx.log(m); }

// Elden Ring base + DLC ids we want to report as owned.
static const uint32_t kOwned[] = { 1245620u, 2778580u, 2778590u, 3655690u };
static bool IsOwned(uint32_t id) {
    for (uint32_t v : kOwned) if (v == id) return true;
    return false;
}

// ---- vtable slot indices for ISteamUser (Valve SDK) ---------------
// 1 = GetHSteamUser, 2 = LoggedOn, 3 = GetSteamID,
// ... 17 = UserHasLicenseForApp, 18 = GetAuthSessionTicket,
// 19 = BeginAuthSession, 20 = EndAuthSession, 21 = CancelAuthTicket,
// 22 = IsUserInGame, 23 = GetEncryptedAppTicket
enum { SLOT_UserHasLicenseForApp = 17, SLOT_GetEncryptedAppTicket = 23 };

static bool  (__fastcall *o_UserHasLicenseForApp)(void*, uint32_t, uint32_t) = nullptr;
static bool  (__fastcall *o_GetEncryptedAppTicket)(void*, void*, uint32_t, uint32_t*, uint32_t*) = nullptr;

static bool __fastcall H_UserHasLicenseForApp(void* self, uint32_t steamID, uint32_t appId) {
    if (IsOwned(appId)) { Log("UserHasLicenseForApp -> TRUE"); return true; }
    return o_UserHasLicenseForApp ? o_UserHasLicenseForApp(self, steamID, appId) : false;
}

static bool __fastcall H_GetEncryptedAppTicket(void* self, void* buf, uint32_t max,
                                               uint32_t* written, uint32_t* crc) {
    // Ask the real one first; if it produced nothing, fabricate a ticket.
    bool ok = o_GetEncryptedAppTicket ? o_GetEncryptedAppTicket(self, buf, max, written, crc) : false;
    if (ok && written && *written > 0) return true;

    if (buf && written && max >= 8) {
        memset(buf, 0xA5, max);
        *written = 8;
        if (crc) *crc = 0x12345678;
        Log("GetEncryptedAppTicket -> fabricated");
        return true;
    }
    return false;
}

// ------------------------------------------------------------------
static bool HookVtableSlot(void* iface, int slot, void* hook, void** orig) {
    if (!iface) return false;
    void** vt = *(void***)iface;
    if (!vt) return false;
    void* target = vt[slot];
    if (!target) return false;
    *orig = target;
    DWORD old;
    VirtualProtect(vt, (slot + 1) * sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
    vt[slot] = hook;
    VirtualProtect(vt, (slot + 1) * sizeof(void*), old, &old);
    return true;
}

extern "C" __declspec(dllexport) int UCO_PluginInit(const UCO_PluginContext* ctx) {
    if (!ctx) return 1;
    g_ctx = *ctx;
    Log("dlc_license_plugin: init");

    if (!g_ctx.steamUser) { Log("no steamUser iface"); return 2; }

    bool a = HookVtableSlot(g_ctx.steamUser, SLOT_UserHasLicenseForApp,
                            (void*)&H_UserHasLicenseForApp,
                            (void**)&o_UserHasLicenseForApp);
    bool b = HookVtableSlot(g_ctx.steamUser, SLOT_GetEncryptedAppTicket,
                            (void*)&H_GetEncryptedAppTicket,
                            (void**)&o_GetEncryptedAppTicket);
    Log(a ? "hooked UserHasLicenseForApp" : "FAILED UserHasLicenseForApp");
    Log(b ? "hooked GetEncryptedAppTicket" : "FAILED GetEncryptedAppTicket");
    return (a || b) ? 0 : 3;
}

extern "C" __declspec(dllexport) void UCO_PluginShutdown(void) {
    Log("dlc_license_plugin: shutdown");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(h);
    return TRUE;
}
