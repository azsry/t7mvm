#pragma once
#include <cstdint>
class coffsets {
public:
	static void get_offsets( );

	uintptr_t base,
		cbuf_addtext;
};

extern coffsets offsets;