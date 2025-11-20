#ifndef MEMORY_H
#define MEMORY_H
#include <Windows.h>
#include <cstdint>
#include <vector>

namespace memory
{
	bool is_readable(std::uint64_t start, size_t size);

	//BYTE, wild card
	std::vector<std::pair<std::uint8_t, bool>> string_to_pattern(const char* pattern);

	//pattern scan for memory region
	std::uint64_t pattern_scan(std::uint64_t start, std::uint64_t size, const char* pattern);
}

#endif