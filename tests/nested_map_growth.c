#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static _Alignas(16) uint8_t test_heap[2*1024*1024];
static size_t test_heap_size = 65536;
#define CITA_ALIGN 16
#define CITA_INDEX_TYPE uint16_t
#define CITA_INFO_LEN 56
#define CITA_INIT_ELEM_AS 32
#define CITA_MAP_SCALE 10
#define CITA_FREE_PATTERN 0xC5
#define CITA_MEM_START ((uintptr_t)test_heap)
#define CITA_MEM_END ((uintptr_t)test_heap + test_heap_size)
#define CITA_MEM_ENLARGE(new_end) { abort(); }
#define CITA_PTR(addr) ((void *)(uintptr_t)(addr))
#define CITA_ADDR(ptr) ((uintptr_t)(ptr))
#define CITA_REPORT(...) { fprintf(stderr, __VA_ARGS__); abort(); }
#define CITA_PRINT(...) { fprintf(stderr, __VA_ARGS__); }
#define CITA_IMPLEMENTATION
#include "../cit_alloc.h"

static void check_links(void)
{
	// Validate every live record without changing the packed allocation table's layout
	for (CITA_INDEX_TYPE i=0; i<ct->elem_count; i++)
	{
		// Reject links to invalid or freed records before dereferencing their neighbors
		cita_elem_t *e = &ct->elem[i];
		if (e->next_index==NAI) continue;
		assert(e->next_index<ct->elem_count && e->prev_index<ct->elem_count);
		assert(ct->elem[e->next_index].prev_index==i);
		assert(ct->elem[e->prev_index].next_index==i);
	}
}

int main(void)
{
	void *blocks[64];
	size_t count = 0;

	// Fill the record table to the point where a nested allocation will need to grow it
	cita_table_init();
	while (ct->elem_count+3<ct->elem_as)
	{
		// Keep the map and metadata table blocked from growing in place
		assert(count<64);
		blocks[count] = cita_malloc(128);
		assert(blocks[count]);
		memset(blocks[count], (int)count+1, 128);
		count++;
	}
	assert(ct->available_index==NAI && ct->elem_count+3==ct->elem_as);
	cita_elem_t *old_table = ct->elem;

	// Simulate a compact map awaiting regrowth while the backing memory remains larger
	memset(test_heap+test_heap_size, CITA_FREE_PATTERN, sizeof(test_heap)-test_heap_size);
	test_heap_size = sizeof(test_heap);
	void *extra = cita_malloc(205);
	assert(ct->elem!=old_table);
	check_links();
	assert(cita_table_find_buffer((uintptr_t)extra, 1)!=NAI);

	// Confirm all allocations remain discoverable and their contents survived nested relocation
	memset(extra, 0x7E, 205);
	for (size_t i=0; i<count; i++)
	{
		// Verify both lookup and payload for every allocation that preceded the map growth
		assert(cita_table_find_buffer((uintptr_t)blocks[i], 1)!=NAI);
		for (size_t j=0; j<128; j++) assert(((uint8_t *)blocks[i])[j]==i+1);
		cita_free(blocks[i]);
		check_links();
	}
	cita_free(extra);
	check_links();
	puts("CITA nested map/table growth test passed");
	return 0;
}
