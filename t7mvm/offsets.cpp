#include "offsets.hpp"
#include <Windows.h>
#include "utils.h"

coffsets offsets;

void coffsets::get_offsets( ) {
	offsets.base = reinterpret_cast< uintptr_t >( GetModuleHandle( NULL ) );
	debug_write(termcolor::yellow, "Base: %p", offsets.base );
	offsets.cbuf_addtext = cutils::find_pattern( "BlackOps3.exe", "48 89 5C 24 ? 48 89 6C 24 ? 56 57 41 57 48 83 EC 30 45 0F B6 F9" );
	debug_write(termcolor::yellow, "CBuf_AddText: %p [%p]", offsets.base + offsets.cbuf_addtext, offsets.cbuf_addtext );
}