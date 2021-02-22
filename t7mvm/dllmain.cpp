#include <Windows.h>
#include <stdio.h>
#include "offsets.hpp"
#include <string>
#include <iostream>
#include "MinHook/include/MinHook.h"
#include "utils.h"

#pragma comment(lib, "winmm.lib")

// 48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 57 48 83 EC 30 45 0F B6 F9 cbuf

typedef void(__fastcall* cbuf_addtext_fn)(void* thisptr, void* rdx, char* cmd, uint8_t a4, char a5);
typedef DWORD(WINAPI* get_tick_count_fn)(void);
typedef DWORD(WINAPI* get_time_fn)(void);
typedef BOOL(WINAPI* query_performace_counter_fn)(LARGE_INTEGER* lpPerformanceCount);

// Speedhack
get_tick_count_fn oGetTickCount = GetTickCount;
get_time_fn otimeGetTime = timeGetTime;
query_performace_counter_fn oQueryPerformanceCounter = QueryPerformanceCounter;

cbuf_addtext_fn CBuf_AddText = nullptr;
logger _log;

#define BUF_SIZE 65535

enum request_type {
	type_timescale = 0,
	type_dllname,
	type_console,
	type_max
};

struct request {
	request(uint32_t mag, request_type _type, char* _data) {
		magic = mag;
		type = _type;
		memcpy(data, _data, 255);
	}

	request() {
		magic = 0;
		type = type_max;
		memset(data, 0, 255);
	}

	int32_t magic;
	request_type type;
	char data[255];
};

DWORD tickcount = 0,
gettime = 0;
int64_t perf_count = 0;
float factor = 1.f;
void* buffer;
uint32_t latest_magic = 0;
char dll_name[255] = { 0 };
bool hijack_cbuf = false;
char* spoofed_cmd = nullptr;


template <typename T1, typename T2, typename T3>
inline bool MAKE_HOOK(T1 pOffset, T2 pHook, T3 pOriginalToStoreIn) {
	if (MH_CreateHook(reinterpret_cast<uintptr_t*>(pOffset), pHook, reinterpret_cast<void**>(pOriginalToStoreIn)) != MH_OK) {
		return false;
	}
	if (MH_EnableHook(reinterpret_cast<uintptr_t*>(pOffset)) != MH_OK) {
		return false;
	}

	return true;
}

DWORD WINAPI hkGetTickCount()
{
	return tickcount + ((oGetTickCount() - tickcount) * factor);
}

DWORD WINAPI hktimeGetTime()
{
	return gettime + ((otimeGetTime() - gettime) * factor);
}

BOOL WINAPI hkQueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)
{
	int64_t current = 0;
	if (!oQueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&current)))
		return FALSE;

	auto newTime = current + ((current - perf_count) * factor);

	*lpPerformanceCount = *reinterpret_cast<LARGE_INTEGER*>(&newTime);

	return TRUE;
}

void __fastcall cbuf_addtext_hk(void* thisptr, void* rdx, char* cmd, uint8_t a4, char a5) {
	if (hijack_cbuf) {
		hijack_cbuf = false;
		cmd = spoofed_cmd;
	}
	_log.write_line("cmd: %s", cmd);
	CBuf_AddText(thisptr, rdx, cmd, a4, a5);
}

template<typename T>
T clamp(T in, T min, T max) {
	if (in > max)
		in = max;
	if (in < min)
		in = min;

	return in;
}

void toClipboard(const std::string &s) {
	OpenClipboard(0);
	EmptyClipboard();
	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, s.size());
	if (!hg) {
		CloseClipboard();
		return;
	}
	memcpy(GlobalLock(hg), s.c_str(), s.size());
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
}

void Init() {
	coffsets::get_offsets();

	tickcount = GetTickCount();
	gettime = timeGetTime();
	QueryPerformanceCounter(reinterpret_cast<LARGE_INTEGER*>(&perf_count));

	//CBuf_AddText = reinterpret_cast< cbuf_addtext_fn >( offsets.cbuf_addtext );

	if (MH_Initialize() != MH_OK)
		return;

	debug_write(termcolor::green, "MinHooked");
	_log.write_line("MinHooked");

	if (!MAKE_HOOK(offsets.cbuf_addtext, &cbuf_addtext_hk, &CBuf_AddText))
		return;

	debug_write(termcolor::green, "Hooked CBuf_AddText: Orig = %p", &CBuf_AddText);
	_log.write_line("Hooked CBuf_AddText: Orig = %p", &CBuf_AddText);

	if (!MAKE_HOOK(oGetTickCount, &hkGetTickCount, &oGetTickCount))
		return;

	debug_write(termcolor::green, "Hooked GetTickCount: Orig = %p", oGetTickCount);
	_log.write_line("Hooked GetTickCount: Orig = %p", oGetTickCount);

	if (!MAKE_HOOK(otimeGetTime, &hktimeGetTime, &otimeGetTime))
		return;

	debug_write(termcolor::green, "Hooked timeGetTime: Orig = %p", otimeGetTime);
	_log.write_line("Hooked timeGetTime: Orig = %p", otimeGetTime);

	if (!MAKE_HOOK(oQueryPerformanceCounter, &hkQueryPerformanceCounter, &oQueryPerformanceCounter))
		return;

	debug_write(termcolor::green, "Hooked QueryPerformanceCounter: Orig = %p", oQueryPerformanceCounter);
	_log.write_line("Hooked QueryPerformanceCounter: Orig = %p", oQueryPerformanceCounter);

	while (true) {
		if (buffer != NULL) {
			debug_write(termcolor::green, "buffer not null");
			auto req = reinterpret_cast<request*>(buffer);

			if (req->magic != latest_magic) {
				_log.write_line("Request received (magic: %i): data = %f", req->magic, *reinterpret_cast<double*>(req->data));
				latest_magic = req->magic;

				switch (req->type) {
				case type_timescale:
					factor = clamp<double>(*reinterpret_cast<double*>(req->data), 0.1f, 10.f);
					break;
				case type_dllname:
					memcpy(dll_name, req->data, sizeof(req->data));
					break;
				case type_console:
					spoofed_cmd = req->data;
					hijack_cbuf = true;
					break;
				}
			}
		}
		Sleep(100);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	{
		//if (AllocConsole()) {
		//	SetConsoleTitle("BlackOps3.exe");
		//	//freopen("CONIN$", "r", stdin);
		//	freopen("CONOUT$", "w", stdout);
		//	//freopen("CONOUT$", "w", stderr);
		//}

		auto map_file = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, "Local\\T7MVM");
		uint32_t latest_magic = 0;

		if (map_file == NULL)
		{
			debug_write(termcolor::red, "Could not open file mapping object (%d)", GetLastError());
		}

		buffer = MapViewOfFile(map_file, // handle to map object
			FILE_MAP_ALL_ACCESS,  // read/write permission
			0,
			0,
			BUF_SIZE);

		if (buffer == NULL)
		{
			debug_write(termcolor::red, "Could not map view of file (%d)", GetLastError());

			CloseHandle(map_file);
		}
		else
			_log.write_line("File mapped at %p\r\n", buffer);

		CreateThread(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(Init), nullptr, NULL, NULL);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		remove(dll_name);
		break;
	}
	return TRUE;
}

