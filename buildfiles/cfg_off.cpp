// Probe: which cfg_root field sits at the offset the reference binary's
// g_cfg-based verbosity byte uses (0x51d4)?
//
// Build: g++ -std=c++20 -I... buildfiles/cfg_off.cpp -o cfg_off && ./cfg_off
#include "Emu/system_config.h"

#include <cstddef>
#include <cstdio>

#define P(field) std::printf("%-44s %#zx\n", #field, offsetof(cfg_root, field))

int main()
{
	P(ppu_debug);
	P(ppu_call_history);
	P(spu_debug);
	P(mfc_debug);
	P(scheduler_loop_detection);
	std::printf("sizeof(cfg_root) = %#zx\n", sizeof(cfg_root));
	return 0;
}