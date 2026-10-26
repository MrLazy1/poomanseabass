// dlc_license_plugin.cpp — UCOnline2 plugin (ABI v1) + diagnostics
// Hooks ISteamUser::UserHasLicenseForApp + GetEncryptedAppTicket so a
// Spacewar-spoofed session stays stable and Elden Ring DLC reads as owned.
// Writes plugin_log.txt next to the game exe for diagnosis.
// Build x64 Release -> dlc_license.dll, drop in the plugins folder.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>

// If you have MinHook, uncomment this and link MinHook.
// #define HAVE_MINHOOK
// #include "MinHook.h"

#ifdef HAVE_MINHOOK
  #define HOOK_CREATE(t,p,f)  MH_CreateHook((LPVOID)(t), (LPVOID)(p), (LPVOID*)(f))
  #define HOOK_ENABLE(t)      MH_EnableHook((LPVOID)(t))
#else
  struct Detour { void* target; void* hook; unsigned char orig[16]; bool on; };
  static Detour* g_detours[8]; static int g_detour_count = 0;
  static bool MakeDetour(void* target, void* hook, Detour* d) {
      d->target = target; d->hook = hook; d->on = false;
      memcpy(d->orig, target, 16);
      DWORD old;
      VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &old);
      unsigned char* p = (unsigned char*)target;
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

// ---------------- logging ----------------
static FILE* g_log = nullptr;

static void LogInit() {
    if (g_log) return;
    char exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    char* s = strrchr(exe, '\\'); if (s) *(s+1)=0;
    char path[MAX_PATH]{};
    snprintf(path, MAX_PATH, "%splugin_log.txt", exe);
    fopen_s(&g_log, path, "a");
}

static void Log(const char* fmt, ...) {
    LogInit();
    if (!g_log) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(g_log, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list ap; va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
}

// ---------------- ABI ----------------
struct UCO_PluginContext {
    void* steamUser;
    void* steamApps;
    void* steamUserStats;
    void* steamUtils;
    uint32_t appId;
    uint32_t ogAppId;
    void (*log)(const char*);
    bool (*registerPatcher)(void* target, void* hook, void** orig);
};

static UCO_PluginContext g_ctx{};

static const uint32_t kOwned[] = { 1245620u, 2778580u, 2778590u, 3655690u };
static bool IsOwned(uint32_t id) {
    for (uint32_t v : kOwned) if (v == id) return true;
    return false;
}

enum { SLOT_UserHasLicenseForApp = 17, SLOT_GetEncryptedAppTicket = 23 };

static bool (__fastcall *o_UserHasLicenseForApp)(void*, uint32_t, uint32_t) = nullptr;
static bool (__fastcall *o_GetEncryptedAppTicket)(void*, void*, uint32_t, uint32_t*, uint32_t*) = nullptr;

static bool __fastcall H_UserHasLicenseForApp(void* self, uint32_t steamID, uint32_t appId) {
    bool owned = IsOwned(appId);
    bool real = o_UserHasLicenseForApp ? o_UserHasLicenseForApp(self, steamID, appId) : false;
    Log("UserHasLicenseForApp appId=%u owned_spoof=%d real=%d -> %d",
        appId, owned, real, (owned || real));
    return owned || real;
}

static bool __fastcall H_GetEncryptedAppTicket(void* self, void* buf, uint32_t max,
                                               uint32_t* written, uint32_t* crc) {
    bool ok = o_GetEncryptedAppTicket ? o_GetEncryptedAppTicket(self, buf, max, written, crc) : false;
    Log("GetEncryptedAppTicket real_ok=%d written=%u", ok, written ? *written : 0);
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

static bool HookVtableSlot(void* iface, int slot, void* hook, void** orig) {
    if (!iface) { Log("HookVtableSlot: iface null (slot %d)", slot); return false; }
    void** vt = *(void***)iface;
    if (!vt) { Log("HookVtableSlot: vtable null (slot %d)", slot); return false; }
    void* target = vt[slot];
    if (!target) { Log("HookVtableSlot: target null (slot %d)", slot); return false; }
    Log("HookVtableSlot slot=%d target=%p", slot, target);
    *orig = target;
    DWORD old;
    VirtualProtect(vt, (slot + 1) * sizeof(void*), PAGE_EXECUTE_READWRITE, &old);
    vt[slot] = hook;
    VirtualProtect(vt, (slot + 1) * sizeof(void*), old, &old);
    return true;
}

extern "C" __declspec(dllexport) int UCO_PluginInit(const UCO_PluginContext* ctx) {
    Log("==== UCO_PluginInit called ====");
    if (!ctx) { Log("ctx == null"); return 1; }
    g_ctx = *ctx;
    Log("ctx: steamUser=%p steamApps=%p appId=%u ogAppId=%u",
        ctx->steamUser, ctx->steamApps, ctx->appId, ctx->ogAppId);

    if (!g_ctx.steamUser) { Log("no steamUser iface -> abort"); return 2; }

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
    Log("==== UCO_PluginShutdown ====");
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD r, LPVOID) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        Log("DllMain: attached, module=%p", (void*)h);
    }
    return TRUE;
}
