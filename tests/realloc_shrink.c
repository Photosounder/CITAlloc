#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static _Alignas(16) uint8_t test_heap[65536];
#define CITA_ALIGN 16
#define CITA_INFO_LEN 0
#define CITA_MEM_START ((uintptr_t)test_heap)
#define CITA_MEM_END ((uintptr_t)(test_heap + sizeof(test_heap)))
#define CITA_MEM_ENLARGE(new_end) { abort(); }
#define CITA_PTR(addr) ((void *)(uintptr_t)(addr))
#define CITA_ADDR(ptr) ((uintptr_t)(ptr))
#define CITA_REPORT(...) { fprintf(stderr, __VA_ARGS__); abort(); }
#define CITA_PRINT(...) { fprintf(stderr, __VA_ARGS__); }
#ifndef TEST_NO_FREE_PATTERN
#define CITA_FREE_PATTERN 0xC5
#endif
#ifdef TEST_MAP
#define CITA_MAP_SCALE 10
#define CITA_GAP_LINKS
#endif
#define CITA_ALWAYS_CHECK_LINKS
#define CITA_IMPLEMENTATION
#include "../cit_alloc.h"

int main(void)
{
	const size_t sizes[] = {2048, 2047, 1024, 17, 16, 1, 0};

	// Check aligned and unaligned tails, unchanged sizes and realloc-to-zero
	for (size_t test=0; test<sizeof(sizes)/sizeof(sizes[0]); test++)
	{
		// Keep a live neighbor after the allocation to catch overwrites beyond its former end
		uint8_t *buffer = cita_malloc(2048);
		uint8_t *neighbor = cita_malloc(64);
		size_t size = sizes[test];
		assert(buffer && neighbor);
		memset(buffer, 0x37, 2048);
		memset(neighbor, 0x6A, 64);

		// Shrink in place while preserving every retained byte and the neighboring allocation
		uint8_t *resized = cita_realloc(buffer, size);
		assert(resized == (size ? buffer : NULL));
		for (size_t i=0; i<size; i++) assert(buffer[i] == 0x37);
		for (size_t i=0; i<64; i++) assert(neighbor[i] == 0x6A);

		// Inspect the released bytes in the fixed test heap with and without the optional wipe pattern
		for (size_t i=size; i<2048; i++)
		{
			#ifdef CITA_FREE_PATTERN
			assert(buffer[i] == CITA_FREE_PATTERN);
			#else
			assert(buffer[i] == 0x37);
			#endif
		}

		// Regrow live buffers in place without disturbing their prefix or their neighbor
		if (size)
		{
			// Check the shared realloc branch also remains correct for growth
			assert(cita_realloc(resized, 2048) == buffer);
			for (size_t i=0; i<size; i++) assert(buffer[i] == 0x37);
			for (size_t i=0; i<64; i++) assert(neighbor[i] == 0x6A);
			cita_free(buffer);
		}
		cita_free(neighbor);
	}

	// Report successful tail, prefix and neighbor checks without requiring a graphical host
	puts("CITA realloc shrink tests passed");
	return 0;
}
