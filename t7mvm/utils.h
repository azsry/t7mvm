#pragma once
#define INRANGE(x,a,b)    (x >= a && x <= b)
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))

//#if defined _DEBUG
//#define debug_write(col, text, ...) cutils::write_coloured(col, text, __VA_ARGS__);
//#else
//#define debug_write(col,text,...)
//#endif

#define debug_write(col, text, ...) cutils::write_coloured(col, text, __VA_ARGS__);

#include <Windows.h>
#include <Psapi.h>
#include <cstdint>
#include <map>
#include <algorithm>
#include <memory>
#include "termcolor.hpp"
#include <fstream>
#include <ctime>
#include <mutex>

class module_t {
public:
	uintptr_t range_start;
	MODULEINFO mod_info;
};

class cutils {
public:
	static uintptr_t load_module_wait(const char* module_name) {
		uintptr_t module_handle = NULL;
		while (!module_handle) {
			module_handle = reinterpret_cast<uintptr_t>(GetModuleHandleA(module_name));
			if (!module_handle)
				Sleep(50);
		}
		return module_handle;
	}

	static uintptr_t find_pattern(const char* module_name, const char* pattern) {
		static std::map<const char*, module_t> cached_modules;
		auto pat = pattern;
		uintptr_t first_match = 0;

		if (cached_modules.find(module_name) == cached_modules.end()) {
			cached_modules[module_name].range_start = reinterpret_cast<uintptr_t>(GetModuleHandleA(module_name));
			GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(cached_modules[module_name].range_start), &cached_modules[module_name].mod_info, sizeof(MODULEINFO));
		}

		const auto range_end = cached_modules[module_name].range_start + cached_modules[module_name].mod_info.SizeOfImage;
		for (auto cur = cached_modules[module_name].range_start; cur < range_end; cur++) {
			if (!*pat)
				return first_match;

			if (*PBYTE(pat) == '\?' || *reinterpret_cast<BYTE*>(cur) == getByte(pat)) {
				if (!first_match)
					first_match = cur;

				if (!pat[2])
					return first_match;

				if (*PWORD(pat) == '\?\?' || *(PBYTE)pat != '\?')
					pat += 3;

				else
					pat += 2; //one ?
			}
			else {
				pat = pattern;
				first_match = 0;
			}
		}
		return NULL;
	}

	static bool is_code_ptr(void * ptr) {
		constexpr const DWORD protect_flags = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

		MEMORY_BASIC_INFORMATION out;
		VirtualQuery(ptr, &out, sizeof out);

		return out.Type
			&& !(out.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			&& out.Protect & protect_flags;
	}

	std::string to_lower(std::string str) const {
		std::transform(str.begin(), str.end(), str.begin(), reinterpret_cast<int(*)(int)>(tolower));

		return str;
	}

	std::string to_upper(std::string str) const {
		std::transform(str.begin(), str.end(), str.begin(), reinterpret_cast<int(*)(int)>(toupper));

		return str;
	}

	char* wstring_to_string(const wchar_t* wstr) const {
		const auto length = wcslen(wstr);
		std::unique_ptr<char[]> c(new char[length + 1]);
		size_t converted = 0;
		wcstombs_s(&converted, c.get(), length + 1, wstr, length);

		return c.get();
	}

	wchar_t* string_to_wstring(const char* str) const {
		const auto length = _mbstrlen(str);
		std::unique_ptr<wchar_t[]> wc(new wchar_t[length + 1]);
		size_t converted = 0;
		mbstowcs_s(&converted, wc.get(), length + 1, str, length);

		return wc.get();
	}

	static bool replace(std::string& str, const std::string& from, const std::string& to) {
		const auto start_pos = str.find(from);
		if (start_pos == std::string::npos)
			return false;
		str.replace(start_pos, from.length(), to);
		return true;
	}

	template <typename T>
	static void write_coloured(T col, const char * text, ...) {
		char _text[4096];
		va_list ap;
		va_start(ap, text);
		vsprintf_s(_text, text, ap);
		strcat_s(_text, "\r\n");
		va_end(ap);

		std::cout << col;
		printf(_text);
		std::cout << termcolor::white;
	}
};

class logger {
private:
	const char* log_name;
	std::mutex mtx;

public:
	logger(const char* filename) {
		log_name = filename;
	}

	logger() {
		log_name = "module.log";
	}

	logger& operator=(logger&& other) noexcept {
		return *this;
	}

	void write_line(const char* fmt, ...) {
		mtx.lock();

		char _text[4096];
		va_list ap;
		va_start(ap, fmt);
		vsprintf_s(_text, fmt, ap);
		va_end(ap);

		time_t rawtime;
		struct tm * timeinfo;
		char buffer[80];

		time(&rawtime);
		timeinfo = localtime(&rawtime);

		strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", timeinfo);

		char fin[4096];

		sprintf_s(fin, "[%s] %s\n", buffer, _text);

		std::ofstream  log_stream(log_name, std::ios::out | std::ios::app);

		if (log_stream.is_open() && log_stream.good()) {
			log_stream << fin;
			log_stream.close();
		}
		mtx.unlock();
	}
};