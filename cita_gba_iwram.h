/* GBA IWRAM adapter for CIT Alloc
 *
 * Define CITA_GBA_IWRAM_IMPLEMENTATION in exactly one C translation unit.
 * Link with __iwram_heap_start and __iwram_heap_end (exclusive).
 * Startup must initialize BSS before use. Initialization is automatic.
 * malloc_iw/free_iw/calloc_iw/realloc_iw do not replace libc names.
 * CIT addresses are 16-bit offsets from the fixed 0x03000000 IWRAM base.
 *
 * Metadata grows within the fixed heap; allocation failure returns NULL.
 * Failed realloc preserves the original allocation.
 *
 * Calls are not interrupt-reentrant: use from main code, or provide external
 * exclusion. Allocator code stays in ROM unless the build places it in IWRAM.
 * This adapter instantiates the CIT core once, with no map or debug strings.
 */
#ifndef H_CITA_GBA_IWRAM
#define H_CITA_GBA_IWRAM

#include <stddef.h>
#include <stdint.h>

extern uint8_t __iwram_heap_start[];
extern uint8_t __iwram_heap_end[];

int cita_gba_iw_init(void);
void *cita_gba_iw_malloc(size_t size);
void cita_gba_iw_free(void *ptr);
void *cita_gba_iw_calloc(size_t nmemb, size_t size);
void *cita_gba_iw_realloc(void *ptr, size_t size);

#define malloc_iw cita_gba_iw_malloc
#define free_iw cita_gba_iw_free
#define calloc_iw cita_gba_iw_calloc
#define realloc_iw cita_gba_iw_realloc

#endif

#if defined(CITA_GBA_IWRAM_IMPLEMENTATION) && !defined(CITA_GBA_IWRAM_IMPLEMENTED)
#define CITA_GBA_IWRAM_IMPLEMENTED

#ifdef H_CITA
#error "Include the GBA adapter before any other CIT core instance in this translation unit"
#endif

static void *cita_gba_iw_memcpy(void *dest, const void *src, size_t size)
{
	// Copy bytes without requiring a libc implementation
	volatile uint8_t *d = dest;
	const volatile uint8_t *s = src;
	for (size_t i = 0; i < size; i++)
	{
		d[i] = s[i];
	}
	return dest;
}

static void *cita_gba_iw_memset(void *dest, int value, size_t size)
{
	// Fill bytes without requiring a libc implementation
	volatile uint8_t *d = dest;
	for (size_t i = 0; i < size; i++)
	{
		d[i] = (uint8_t) value;
	}
	return dest;
}

#ifndef CITA_GBA_IWRAM_BASE
#define CITA_GBA_IWRAM_BASE ((uintptr_t) 0x03000000u)
#endif

static void *cita_gba_iw_pointer(uint16_t address)
{
	// Convert a compact IWRAM offset to a native pointer
	return (void *) (CITA_GBA_IWRAM_BASE + address);
}

static uint16_t cita_gba_iw_address(const void *ptr)
{
	// Reject pointers outside the canonical 32 KiB IWRAM address range
	uintptr_t address = (uintptr_t) ptr;
	if (ptr == NULL || address < CITA_GBA_IWRAM_BASE
		|| address >= CITA_GBA_IWRAM_BASE + 0x8000u)
	{
		return ptr == NULL ? 0 : UINT16_MAX;
	}

	// Convert a native IWRAM pointer to its compact offset
	return (uint16_t) (address - CITA_GBA_IWRAM_BASE);
}

#define CITA_ALIGN 4
#define CITA_INDEX_TYPE uint16_t
#define CITA_ADDR_TYPE uint16_t
#define CITA_INFO_LEN 0
#define CITA_EXCL_TIME
#define CITA_EXCLUDE_STRING_H
#define CITA_MEM_START ((uint16_t) ((uintptr_t) __iwram_heap_start - CITA_GBA_IWRAM_BASE))
#define CITA_MEM_END ((uint16_t) ((uintptr_t) __iwram_heap_end - CITA_GBA_IWRAM_BASE))
#define CITA_MEM_ENLARGE(new_end) { (void) (new_end); }
#define CITA_PTR(addr) cita_gba_iw_pointer(addr)
#define CITA_ADDR(ptr) cita_gba_iw_address(ptr)
#define CITA_PRINT(...) {}
#define CITA_REPORT(...) {}
#define memcpy cita_gba_iw_memcpy
#define memset cita_gba_iw_memset

#define cita_malloc cita_gba_iw_core_malloc
#define cita_free cita_gba_iw_core_free
#define cita_calloc cita_gba_iw_core_calloc
#define cita_realloc cita_gba_iw_core_realloc
#define cita_table_find_buffer cita_gba_iw_table_find_buffer
#define cita_find_end_addr cita_gba_iw_find_end_addr
#define cita_inc_event_counter cita_gba_iw_inc_event_counter
#define cita_align_up cita_gba_iw_align_up
#define cita_free_space_after cita_gba_iw_free_space_after
#define cita_range_after_space cita_gba_iw_range_after_space
#define cita_erase_to_mem_end cita_gba_iw_erase_to_mem_end
#define cita_free_core cita_gba_iw_free_core
#define cita_gap_init_elem cita_gba_iw_gap_init_elem
#define cita_gap_is_boundary cita_gba_iw_gap_is_boundary
#define cita_gap_span_start cita_gba_iw_gap_span_start
#define cita_gap_span_end cita_gba_iw_gap_span_end
#define cita_gap_rebuild_span cita_gba_iw_gap_rebuild_span
#define cita_gap_refresh cita_gba_iw_gap_refresh
#define cita_gap_first_at_or_after cita_gba_iw_gap_first_at_or_after
#define cita_gap_next_linked cita_gba_iw_gap_next_linked
#define cita_gap_find_free_space cita_gba_iw_gap_find_free_space
#define cita_map_rebuild_range cita_gba_iw_map_rebuild_range
#define cita_map_space_value cita_gba_iw_map_space_value
#define cita_map_cell_range cita_gba_iw_map_cell_range
#define cita_map_init_cells cita_gba_iw_map_init_cells
#define cita_map_addr_cells cita_gba_iw_map_addr_cells
#define cita_map_include_range cita_gba_iw_map_include_range
#define cita_map_include_addr_range cita_gba_iw_map_include_addr_range
#define cita_map_include_elem cita_gba_iw_map_include_elem
#define cita_map_include_free_space_after cita_gba_iw_map_include_free_space_after
#define cita_map_include_moved_elem cita_gba_iw_map_include_moved_elem
#define cita_map_ensure_capacity cita_gba_iw_map_ensure_capacity
#define cita_map_count_for_mem_end cita_gba_iw_map_count_for_mem_end
#define cita_find_payload_end_addr cita_gba_iw_find_payload_end_addr
#define cita_map_count_for_payload_end cita_gba_iw_map_count_for_payload_end
#define cita_shrink_map cita_gba_iw_shrink_map
#define cita_map_set_elem_range cita_gba_iw_map_set_elem_range
#define cita_map_index_is_live cita_gba_iw_map_index_is_live
#define cita_map_find_rebuild_start cita_gba_iw_map_find_rebuild_start
#define cita_map_next_cell_index cita_gba_iw_map_next_cell_index
#define cita_map_next_gap_index cita_gba_iw_map_next_gap_index
#define cita_map_rebuild_free_spaces cita_gba_iw_map_rebuild_free_spaces
#define cita_map_find_free_space cita_gba_iw_map_find_free_space
#define cita_map_update_range cita_gba_iw_map_update_range
#define cita_shrink_new_end cita_gba_iw_shrink_new_end
#define cita_enlarge_memory cita_gba_iw_enlarge_memory
#define cita_shrink_memory cita_gba_iw_shrink_memory
#define cita_check_links cita_gba_iw_check_links
#define cita_check_links_internal cita_gba_iw_check_links_internal
#define cita_table_init cita_gba_iw_table_init
#define cita_table_t cita_gba_iw_table_t
#define cita_elem_t cita_gba_iw_elem_t
#define cita_extra_t cita_gba_iw_extra_t
#define cita_map_cell_t cita_gba_iw_map_cell_t
#define cita_input_info cita_gba_iw_input_info
#define ct cita_gba_iw_table

#define CITA_IMPLEMENTATION
#include "cit_alloc.h"
#undef CITA_IMPLEMENTATION

#undef cita_malloc
#undef cita_free
#undef cita_calloc
#undef cita_realloc
#undef cita_table_find_buffer
#undef cita_find_end_addr
#undef cita_inc_event_counter
#undef cita_align_up
#undef cita_free_space_after
#undef cita_range_after_space
#undef cita_erase_to_mem_end
#undef cita_free_core
#undef cita_gap_init_elem
#undef cita_gap_is_boundary
#undef cita_gap_span_start
#undef cita_gap_span_end
#undef cita_gap_rebuild_span
#undef cita_gap_refresh
#undef cita_gap_first_at_or_after
#undef cita_gap_next_linked
#undef cita_gap_find_free_space
#undef cita_map_rebuild_range
#undef cita_map_space_value
#undef cita_map_cell_range
#undef cita_map_init_cells
#undef cita_map_addr_cells
#undef cita_map_include_range
#undef cita_map_include_addr_range
#undef cita_map_include_elem
#undef cita_map_include_free_space_after
#undef cita_map_include_moved_elem
#undef cita_map_ensure_capacity
#undef cita_map_count_for_mem_end
#undef cita_find_payload_end_addr
#undef cita_map_count_for_payload_end
#undef cita_shrink_map
#undef cita_map_set_elem_range
#undef cita_map_index_is_live
#undef cita_map_find_rebuild_start
#undef cita_map_next_cell_index
#undef cita_map_next_gap_index
#undef cita_map_rebuild_free_spaces
#undef cita_map_find_free_space
#undef cita_map_update_range
#undef cita_shrink_new_end
#undef cita_enlarge_memory
#undef cita_shrink_memory
#undef cita_check_links
#undef cita_check_links_internal
#undef cita_table_init
#undef cita_table_t
#undef cita_elem_t
#undef cita_extra_t
#undef cita_map_cell_t
#undef cita_input_info
#undef ct

#undef memcpy
#undef memset

int cita_gba_iw_init(void)
{
	// Keep existing allocations when initialization has already completed
	if (cita_gba_iw_table != NULL)
	{
		return 1;
	}

	// Validate the linker-designated range within canonical IWRAM
	uintptr_t begin = (uintptr_t) __iwram_heap_start;
	uintptr_t end = (uintptr_t) __iwram_heap_end;
	if ((begin & 7u) != 0 || begin < CITA_GBA_IWRAM_BASE || end < begin
		|| end > CITA_GBA_IWRAM_BASE + 0x8000u)
	{
		return 0;
	}

	// Initialize memory before the core reads its table state
	cita_gba_iw_memset(__iwram_heap_start, 0, end - begin);
	cita_gba_iw_table_init();
	return cita_gba_iw_table != NULL;
}

void *cita_gba_iw_malloc(size_t size)
{
	// Reject requests that cannot fit before arithmetic in the allocator core
	if (!cita_gba_iw_init() || size > (size_t) (CITA_MEM_END - CITA_MEM_START))
	{
		return NULL;
	}

	// Allocate from the fixed linker-designated IWRAM region
	return cita_gba_iw_core_malloc(size);
}

void cita_gba_iw_free(void *ptr)
{
	// Ignore null pointers and calls made before the first allocation
	if (ptr == NULL || cita_gba_iw_table == NULL)
	{
		return;
	}

	// Release the allocation through the core's pointer validation
	cita_gba_iw_core_free(ptr);
}

void *cita_gba_iw_calloc(size_t nmemb, size_t size)
{
	// Initialize the fixed heap before using the shared checked calloc
	if (!cita_gba_iw_init())
	{
		return NULL;
	}
	return cita_gba_iw_core_calloc(nmemb, size);
}

void *cita_gba_iw_realloc(void *ptr, size_t size)
{
	// Handle allocation and release without requiring a spare metadata entry
	if (ptr == NULL)
	{
		return cita_gba_iw_malloc(size);
	}
	if (size == 0)
	{
		cita_gba_iw_free(ptr);
		return NULL;
	}

	// Reject requests that cannot fit in the fixed heap
	if (cita_gba_iw_table == NULL
		|| size > (size_t) (CITA_MEM_END - CITA_MEM_START))
	{
		return NULL;
	}

	// Resize within the fixed heap without allowing address arithmetic to wrap
	return cita_gba_iw_core_realloc(ptr, size);
}

#undef CITA_ALIGN
#undef CITA_INDEX_TYPE
#undef CITA_ADDR_TYPE
#undef CITA_INFO_LEN
#undef CITA_EXCL_TIME
#undef CITA_EXCLUDE_STRING_H
#undef CITA_INIT_ELEM_AS
#undef CITA_MEM_START
#undef CITA_MEM_END
#undef CITA_MEM_ENLARGE
#undef CITA_PTR
#undef CITA_ADDR
#undef CITA_PRINT
#undef CITA_REPORT

#endif
