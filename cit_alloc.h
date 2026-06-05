/*                  Compact Info Table Allocator
                          by Michel Rouzic

The goal of CIT Alloc is to keep a compact information table that
contains 100% of the information about allocated buffers and the
free spaces between them in a compact table that can contain extra
information about each buffer for the purpose of visualising the
memory layout.

- There is no overhead outside of the table for buffers, so a
  buffer may well start right after the previous one.
- The information table is compact and movable so it can be 
  conveniently copied to another memory outside of its module for
  analysis.
- The information table is just a buffer among others that can be
  enlarged and moved by realloc().
- Elements of the table point to each other, but the table is
  meant to be traversed linearly.
- The table naturally prevents operations on invalid buffers such
  as double-freeing. Attempting to free or realloc a non-heap
  buffer is also detected and reported.
- The following errors are reported through a printf-like macro:
	- Trying to enlarge memory more than possible
	- Giving free/realloc a pointer that is inside a buffer
	- Giving free/realloc a pointer that isn't in the heap
	- Giving free/realloc a pointer that isn't found
	- Zero size malloc
- Any function can make cita_input_info point to a string to
  override any info until cita_input_info is set to NULL again.
  For instance you can do cita_input_info = "my_function():123";
  so that any allocation will store that info until you unset it.

How can the information table be read correctly:
- The 4 bytes "CITA" will always be written at CITA_MEM_START.
- Following this signature, a 4-byte integer indicates the offset
  from CITA_MEM_START to a string that contains enough information
  to infer how to decode the rest of the data, such as the CIT
  Alloc version or the size of various table elements.
- Consult cita_table_t to find data at the right offsets, but keep
  in mind that the offset will be different depending on whether
  it's in 32 or 64 bits (for instance you might have a 64-bit host
  but a 32-bit CIT Alloc-using module).
- Regularly update timestamp at its correct offset so that it can
  be used for storing buffer creation and modification dates.

Defines that need to be provided before including this file:
CITA_ALIGN: Alignment size in bytes, e.g. 16
CITA_INDEX_TYPE: Index type defined as uint?_t
CITA_INFO_LEN: length of the info string in the table
CITA_MEM_START: Start address of the memory where everything will
  be allocated and written
CITA_MEM_END: A way to obtain the address of the end of the memory
CITA_MEM_ENLARGE(new_end): A way to enlarge the memory, doesn't
  need to return anything
CITA_PTR(addr): How to turn a CITA address into an actual pointer.
  This enables the use of CITA inside buffers where "addresses"
  are indices.
CITA_ADDR(ptr): Does the reverse of CITA_PTR()
CITA_PRINT(fmt, ...): A printf-like function to just print
CITA_REPORT(fmt, ...): A printf-like function to report serious
  errors by the caller

Optional:
CITA_MAP_SCALE: Enables the map and defines the power of 2 for the
  size of one cell of the map, e.g. 14 means a cell covers 16 kB.
CITA_FREE_PATTERN: A byte pattern, e.g. 0xE6, that if set will be
  used to erase all unused bytes between CITA_MEM_START and
  CITA_MEM_END
CITA_INIT_ELEM_AS: Changes the default initial allocation size of
  the CITA table
CITA_ALWAYS_CHECK_LINKS: All functions will check the integrity of
  the links between the table elements
CITA_EXCLUDE_STRING_H: To avoid including <string.h>
CITA_EXCL_TIME: Exclude timestamps from the info table
CITA_TLS: Storage-class specifier for the input info pointer
CITA_TLS_HEAP: Storage-class specifier for globals, used when
  different threads have different heaps
CITA_ADDR_TYPE: Address type defined as uint?_t
CITA_MAPINDEX_TYPE: Map range index type, depends on the maximum
  expected cell count in the map
CITA_MAPSIZE_TYPE: Map free-space size type. Defaults to
  CITA_MAPINDEX_TYPE
CITA_GAP_LINKS: Add free-space run boundary links to each entry
CITA_PADDING: Padding size between buffers. Reveals buffer
  overruns.
CITA_TIME_IS_COUNTER: Makes the timestamps be cita_event_counter

*/

#ifndef H_CITA
#define H_CITA

#include <stdint.h>

extern void *cita_malloc(size_t size);
extern void cita_free(void *ptr);
extern void *cita_calloc(size_t nmemb, size_t size);
extern void *cita_realloc(void *ptr, size_t size);

#ifndef CITA_ADDR_TYPE
  #define CITA_ADDR_TYPE uintptr_t
#endif

#ifndef CITA_MAPINDEX_TYPE
  #define CITA_MAPINDEX_TYPE uint32_t
#endif

#ifndef CITA_MAPSIZE_TYPE
  #define CITA_MAPSIZE_TYPE CITA_MAPINDEX_TYPE
#endif

#ifndef CITA_TLS
  #define CITA_TLS
#endif

#ifndef CITA_TLS_HEAP
  #define CITA_TLS_HEAP
#endif

extern int32_t cita_table_find_buffer(CITA_ADDR_TYPE addr, const int start_only);
extern CITA_ADDR_TYPE cita_find_end_addr();

CITA_TLS extern char *cita_input_info;

#endif // H_CITA

#ifdef CITA_IMPLEMENTATION

#ifndef CITA_EXCLUDE_STRING_H
  #include <string.h>
#endif

// Not An Index
#define NAI ((CITA_INDEX_TYPE) -1)

#ifndef CITA_INIT_ELEM_AS
  #define CITA_INIT_ELEM_AS 16
#endif

#ifndef CITA_PADDING
  #define CITA_PADDING 0
#endif

#ifdef CITA_MAP_SCALE
  #define CITA_MAP_CELL_SIZE ((CITA_ADDR_TYPE) 1 << CITA_MAP_SCALE)
  #define CITA_MAP_COUNT_MIN ((CITA_MEM_END-CITA_MEM_START + CITA_MAP_CELL_SIZE-1) >> CITA_MAP_SCALE)
  #define CITA_MAP_INDEX_NAI ((CITA_MAPINDEX_TYPE) -1)
  #define CITA_MAP_SPACE_MAX ((CITA_MAPSIZE_TYPE) -1)
#endif

#pragma pack(push, 1)
typedef struct
{
	#ifndef CITA_EXCL_TIME
	int32_t time_created, time_modified;
	#endif
	#ifdef CITA_ALWAYS_CHECK_LINKS
	int8_t link;
	#endif
	#if CITA_INFO_LEN > 0
	char info[CITA_INFO_LEN];
	#endif
} cita_extra_t;

typedef struct
{
	CITA_INDEX_TYPE prev_index, next_index;
	#ifdef CITA_GAP_LINKS
	CITA_INDEX_TYPE prev_gap_index, next_gap_index;
	#endif
	CITA_ADDR_TYPE addr, addr_end;
	#ifdef CITA_MAP_SCALE
	CITA_MAPINDEX_TYPE map_start, map_end;
	#endif
	cita_extra_t extra;
} cita_elem_t;

#ifdef CITA_MAP_SCALE
typedef struct
{
	CITA_INDEX_TYPE index;
	CITA_MAPSIZE_TYPE free_space;
} cita_map_cell_t;
#endif
#pragma pack(pop)

typedef struct
{
	char cita_signature[4];
	int32_t version_offset, available_index;
	volatile int32_t timestamp;	// meant to be updated by the host
	cita_elem_t *elem;
	size_t elem_count, elem_as;
	char cita_version[96];
} cita_table_t;

CITA_TLS_HEAP cita_table_t *ct=NULL;
CITA_TLS char *cita_input_info=NULL;
CITA_TLS_HEAP int cita_event_counter = -1;
void cita_inc_event_counter()
{
	cita_event_counter++;
	#ifdef CITA_TIME_IS_COUNTER
	ct->timestamp = cita_event_counter;
	#endif
}

CITA_ADDR_TYPE cita_align_down(CITA_ADDR_TYPE addr)
{
	return addr & ~(CITA_ALIGN-1);
}

CITA_ADDR_TYPE cita_align_up(CITA_ADDR_TYPE addr)
{
	return cita_align_down(addr+CITA_ALIGN-1 + CITA_PADDING);
}

int cita_free_space_after(CITA_INDEX_TYPE index, CITA_ADDR_TYPE *addr, CITA_ADDR_TYPE *addr_end)
{
	// Find the reusable free space after an element
	if (index == NAI || index >= ct->elem_count)
		return 0;

	cita_elem_t *el = &ct->elem[index];
	if (el->next_index == 0 || el->next_index == NAI)
		return 0;

	*addr = cita_align_up(el->addr_end);
	*addr_end = ct->elem[el->next_index].addr;
	return *addr < *addr_end;
}

CITA_ADDR_TYPE cita_range_after_space(CITA_INDEX_TYPE index)
{
	// Return the reusable free space after an element
	CITA_ADDR_TYPE addr, addr_end;
	return cita_free_space_after(index, &addr, &addr_end) ? addr_end - addr : 0;
}

void cita_erase_to_mem_end(CITA_ADDR_TYPE start)
{
	#ifdef CITA_FREE_PATTERN
	if (start < CITA_MEM_END)
		memset(CITA_PTR(start), CITA_FREE_PATTERN, CITA_MEM_END - start);
	#endif
}

#ifdef CITA_GAP_LINKS
void cita_gap_init_elem(CITA_INDEX_TYPE index)
{
	// Clear gap-owner hints for an unavailable element
	ct->elem[index].prev_gap_index = NAI;
	ct->elem[index].next_gap_index = NAI;
}

int cita_gap_owns_space(CITA_INDEX_TYPE index)
{
	// Check whether an element owns a reusable free space
	CITA_ADDR_TYPE addr, addr_end;
	return cita_free_space_after(index, &addr, &addr_end);
}

CITA_INDEX_TYPE cita_gap_span_start(CITA_INDEX_TYPE index)
{
	// Find the first entry after the previous reusable free space
	while (index != 0)
	{
		CITA_INDEX_TYPE prev_index = ct->elem[index].prev_index;
		if (cita_gap_owns_space(prev_index))
			break;
		index = prev_index;
	}

	return index;
}

CITA_INDEX_TYPE cita_gap_span_end(CITA_INDEX_TYPE index)
{
	// Find the last entry before the next reusable free space
	while (!cita_gap_owns_space(index) && ct->elem[index].next_index != 0)
	{
		index = ct->elem[index].next_index;
	}

	return index;
}

void cita_gap_rebuild_span(CITA_INDEX_TYPE start, CITA_INDEX_TYPE end)
{
	// Rebuild gap-run hints across a linked span
	for (CITA_INDEX_TYPE index = start; ; index = ct->elem[index].next_index)
	{
		ct->elem[index].prev_gap_index = start;
		ct->elem[index].next_gap_index = end;
		if (index == end)
			break;
	}
}

void cita_gap_unlink(CITA_INDEX_TYPE index)
{
	// Clear gap-owner hints before making an element unavailable
	cita_gap_init_elem(index);
}

void cita_gap_refresh(CITA_INDEX_TYPE index)
{
	// Rebuild gap-run hints around an element
	if (index == NAI || index >= ct->elem_count || ct->elem[index].next_index == NAI)
		return;

	// Rebuild the run containing this element
	cita_gap_rebuild_span(cita_gap_span_start(index), cita_gap_span_end(index));

	// Rebuild the run after this element when it now owns a gap
	if (cita_gap_owns_space(index) && ct->elem[index].next_index != 0)
	{
		CITA_INDEX_TYPE next_index = ct->elem[index].next_index;
		cita_gap_rebuild_span(next_index, cita_gap_span_end(next_index));
	}
}

CITA_INDEX_TYPE cita_gap_first_at_or_after(CITA_INDEX_TYPE index)
{
	// Read the entry before the next reusable free space
	if (index == NAI || index >= ct->elem_count || ct->elem[index].next_index == NAI)
		return NAI;

	return ct->elem[index].next_gap_index;
}

CITA_INDEX_TYPE cita_gap_next_linked(CITA_INDEX_TYPE index)
{
	// Find the next entry before a reusable free space
	if (index == NAI || index >= ct->elem_count || ct->elem[index].next_index == 0)
		return NAI;

	return ct->elem[ct->elem[index].next_index].next_gap_index;
}

CITA_INDEX_TYPE cita_gap_find_free_space(CITA_ADDR_TYPE required_space)
{
	// Search gap owners for a reusable free space large enough
	for (CITA_INDEX_TYPE index = ct->elem[0].next_gap_index; index != NAI; index = cita_gap_next_linked(index))
		if (cita_range_after_space(index) >= required_space)
			return index;

	return NAI;
}
#endif

int cita_map_update_skip = 1;
#ifdef CITA_MAP_SCALE
size_t cita_map_count = 0;
int8_t cita_map_ready = 0, cita_map_resizing = 0;

void cita_map_rebuild_range(size_t im0, size_t im1);

CITA_MAPSIZE_TYPE cita_map_space_value(CITA_ADDR_TYPE size)
{
	// Convert byte sizes to aligned map units and cap the result
	CITA_ADDR_TYPE value = size / CITA_ALIGN;
	if (size && value == 0)
		value = 1;
	if (value > (CITA_ADDR_TYPE) CITA_MAP_SPACE_MAX)
		return CITA_MAP_SPACE_MAX;
	return (CITA_MAPSIZE_TYPE) value;
}

void cita_map_cell_range(size_t im, CITA_ADDR_TYPE *cell_start, CITA_ADDR_TYPE *cell_end)
{
	// Compute the address range covered by a map cell
	*cell_start = CITA_MEM_START + ((CITA_ADDR_TYPE) im << CITA_MAP_SCALE);
	*cell_end = *cell_start + CITA_MAP_CELL_SIZE;
	if (*cell_end < *cell_start)
		*cell_end = (CITA_ADDR_TYPE) -1;
}

void cita_map_init_cells(cita_map_cell_t *map, size_t im0, size_t im1)
{
	// Initialise map cells to empty allocation and free-space entries
	for (size_t im = im0; im <= im1; im++)
	{
		map[im].index = NAI;
		map[im].free_space = 0;
	}
}

void cita_map_addr_cells(CITA_ADDR_TYPE addr, CITA_ADDR_TYPE addr_end, size_t *im0, size_t *im1)
{
	// Convert an address range to map cells
	if (addr_end <= addr)
	{
		*im0 = 1;
		*im1 = 0;
		return;
	}

	if (addr < CITA_MEM_START)
		addr = CITA_MEM_START;
	if (addr_end > CITA_MEM_END)
		addr_end = CITA_MEM_END;
	if (addr_end <= addr)
	{
		*im0 = 1;
		*im1 = 0;
		return;
	}

	*im0 = (addr       - CITA_MEM_START) >> CITA_MAP_SCALE;
	*im1 = (addr_end-1 - CITA_MEM_START) >> CITA_MAP_SCALE;
}

void cita_map_include_range(size_t *im0, size_t *im1, size_t r0, size_t r1)
{
	// Add a cell range to an existing rebuild range
	if (r0 > r1)
		return;
	if (*im0 > *im1)
	{
		*im0 = r0;
		*im1 = r1;
		return;
	}
	if (r0 < *im0)
		*im0 = r0;
	if (r1 > *im1)
		*im1 = r1;
}

void cita_map_include_addr_range(size_t *im0, size_t *im1, CITA_ADDR_TYPE addr, CITA_ADDR_TYPE addr_end)
{
	// Add an address range to an existing rebuild range
	size_t r0, r1;
	cita_map_addr_cells(addr, addr_end, &r0, &r1);
	cita_map_include_range(im0, im1, r0, r1);
}

void cita_map_include_elem(size_t *im0, size_t *im1, CITA_INDEX_TYPE index)
{
	// Add an element's address range to an existing rebuild range
	size_t r0, r1;
	cita_elem_t *el = &ct->elem[index];
	cita_map_addr_cells(el->addr, el->addr_end, &r0, &r1);
	cita_map_include_range(im0, im1, r0, r1);
}

int cita_map_free_space_after(CITA_INDEX_TYPE index, CITA_ADDR_TYPE *addr, CITA_ADDR_TYPE *addr_end)
{
	// Find the reusable free space after an element
	return cita_free_space_after(index, addr, addr_end);
}

void cita_map_include_free_space_after(size_t *im0, size_t *im1, CITA_INDEX_TYPE index)
{
	// Add the free space after an element to an existing rebuild range
	CITA_ADDR_TYPE addr, addr_end;
	if (cita_map_free_space_after(index, &addr, &addr_end))
		cita_map_include_addr_range(im0, im1, addr, addr_end);
}

void cita_map_include_moved_elem(size_t *im0, size_t *im1, CITA_INDEX_TYPE index, CITA_INDEX_TYPE old_prev_index, CITA_ADDR_TYPE old_addr, CITA_ADDR_TYPE old_addr_end)
{
	// Add an element's old and current positions after skipped map updates
	cita_map_include_addr_range(im0, im1, old_addr, old_addr_end);
	cita_map_include_free_space_after(im0, im1, old_prev_index);
	cita_map_include_elem(im0, im1, index);
	cita_map_include_free_space_after(im0, im1, ct->elem[index].prev_index);
	cita_map_include_free_space_after(im0, im1, index);
}

void cita_map_ensure_capacity()
{
	if (!cita_map_ready || cita_map_resizing)
		return;

	while (cita_map_count < CITA_MAP_COUNT_MIN)
	{
		size_t max_count = (size_t) CITA_MAP_INDEX_NAI;
		if (CITA_MAP_COUNT_MIN > max_count)
		{
			CITA_REPORT("cita_map_ensure_capacity(): map needs %zd cells but CITA_MAPINDEX_TYPE can only index %zd cells. Input info says \"%s\"", CITA_MAP_COUNT_MIN, max_count, cita_input_info);
			return;
		}

		size_t old_count = cita_map_count;
		size_t new_count = old_count;
		if (new_count == 0)
			new_count = CITA_MAP_COUNT_MIN;
		else if (new_count > max_count / 2)
			new_count = max_count;
		else
			new_count *= 2;

		while (new_count < CITA_MAP_COUNT_MIN)
		{
			if (new_count > max_count / 2)
			{
				new_count = max_count;
				break;
			}
			new_count *= 2;
		}

		CITA_INDEX_TYPE old_map_prev_index = ct->elem[2].prev_index;
		CITA_ADDR_TYPE old_map_addr = ct->elem[2].addr;
		CITA_ADDR_TYPE old_map_addr_end = ct->elem[2].addr_end;
		CITA_INDEX_TYPE old_table_prev_index = ct->elem[1].prev_index;
		CITA_ADDR_TYPE old_table_addr = ct->elem[1].addr;
		CITA_ADDR_TYPE old_table_addr_end = ct->elem[1].addr_end;

		int update_skip = cita_map_update_skip;
		cita_map_update_skip = 1;
		cita_map_resizing = 1;
		void *map_ptr = cita_realloc(CITA_PTR(ct->elem[2].addr), new_count * sizeof(cita_map_cell_t));
		cita_map_resizing = 0;
		cita_map_update_skip = update_skip;

		if (map_ptr == NULL)
		{
			CITA_REPORT("cita_map_ensure_capacity(): failed to enlarge map from %zd to %zd cells. Input info says \"%s\"", old_count, new_count, cita_input_info);
			return;
		}

		cita_map_count = new_count;
		cita_map_cell_t *map = CITA_PTR(ct->elem[2].addr);
		cita_map_init_cells(map, old_count, new_count - 1);

		// Rebuild cells around the old and new map positions after resizing
		if (!cita_map_update_skip)
		{
			size_t im0 = 1, im1 = 0;
			if (old_table_prev_index != ct->elem[1].prev_index || old_table_addr != ct->elem[1].addr || old_table_addr_end != ct->elem[1].addr_end)
				cita_map_include_moved_elem(&im0, &im1, 1, old_table_prev_index, old_table_addr, old_table_addr_end);
			cita_map_include_moved_elem(&im0, &im1, 2, old_map_prev_index, old_map_addr, old_map_addr_end);
			cita_map_rebuild_range(im0, im1);
		}
	}
}

void cita_map_elem_cells(CITA_INDEX_TYPE index, size_t *im0, size_t *im1)
{
	cita_elem_t *el = &ct->elem[index];
	cita_map_addr_cells(el->addr, el->addr_end, im0, im1);
}

void cita_map_set_elem_range(CITA_INDEX_TYPE index)
{
	size_t im0, im1;
	cita_map_elem_cells(index, &im0, &im1);
	if (im0 <= im1)
	{
		ct->elem[index].map_start = (CITA_MAPINDEX_TYPE) im0;
		ct->elem[index].map_end = (CITA_MAPINDEX_TYPE) im1;
	}
	else
	{
		ct->elem[index].map_start = CITA_MAP_INDEX_NAI;
		ct->elem[index].map_end = 0;
	}
}

int cita_map_index_is_live(CITA_INDEX_TYPE index)
{
	// Check whether a map cell still points to a linked element
	return index == 0 || (index != NAI && index < ct->elem_count && ct->elem[index].next_index != NAI);
}

CITA_INDEX_TYPE cita_map_find_rebuild_start(cita_map_cell_t *map, size_t im0, size_t im1, CITA_ADDR_TYPE rebuild_start)
{
	CITA_INDEX_TYPE index = NAI;

	// Try to anchor from a valid cell inside the rebuild range
	for (size_t im = im0; im <= im1; im++)
		if (cita_map_index_is_live(map[im].index))
		{
			index = map[im].index;
			break;
		}

	// Look backwards for the nearest valid map cell if this range is empty
	for (size_t im = im0; index == NAI && im > 0; )
	{
		im--;
		if (cita_map_index_is_live(map[im].index))
			index = map[im].index;
	}

	// Fall back to the start of the linked list
	if (index == NAI)
		index = 0;

	// Move backwards to the first element that may overlap the first rebuilt cell
	while (index && ct->elem[ct->elem[index].prev_index].addr_end > rebuild_start)
		index = ct->elem[index].prev_index;

	// Start from the first real allocation if the base marker was found
	if (index == 0)
		index = ct->elem[0].next_index;

	// Move forwards past elements that end before the first rebuilt cell
	while (index && ct->elem[index].addr_end <= rebuild_start)
		index = ct->elem[index].next_index;

	return index;
}

CITA_INDEX_TYPE cita_map_find_gap_start(CITA_INDEX_TYPE index)
{
	// Start with the gap before the first rebuilt allocation
	if (index == NAI)
		return 0;
	return index ? ct->elem[index].prev_index : 0;
}

CITA_INDEX_TYPE cita_map_next_cell_index(CITA_INDEX_TYPE index, CITA_ADDR_TYPE cell_start)
{
	// Move forwards to the first element that may overlap the cell
	while (index)
	{
		if (index == 1 || index == 2 || ct->elem[index].addr_end <= cell_start)
		{
			index = ct->elem[index].next_index;
			continue;
		}

		break;
	}

	return index;
}

CITA_INDEX_TYPE cita_map_next_gap_index(CITA_INDEX_TYPE index, CITA_ADDR_TYPE cell_start)
{
	// Move forwards to the first free space that may overlap the cell
	#ifdef CITA_GAP_LINKS
	index = cita_gap_first_at_or_after(index);
	while (index != NAI)
	{
		CITA_ADDR_TYPE addr, addr_end;
		if (cita_free_space_after(index, &addr, &addr_end) && addr_end > cell_start)
			break;
		index = cita_gap_next_linked(index);
	}
	#else
	while (index != NAI)
	{
		CITA_ADDR_TYPE addr, addr_end;
		if (cita_free_space_after(index, &addr, &addr_end) && addr_end > cell_start)
			break;

		if (ct->elem[index].next_index == 0)
			return NAI;
		index = ct->elem[index].next_index;
	}
	#endif

	return index;
}

void cita_map_store_free_space(cita_map_cell_t *map, size_t im0, size_t im1, CITA_ADDR_TYPE addr, CITA_ADDR_TYPE addr_end)
{
	// Find the rebuilt cells overlapped by this reusable free space
	size_t gap_im0, gap_im1;
	cita_map_addr_cells(addr, addr_end, &gap_im0, &gap_im1);
	if (gap_im0 < im0)
		gap_im0 = im0;
	if (gap_im1 > im1)
		gap_im1 = im1;
	if (gap_im0 > gap_im1)
		return;

	// Store the free-space size in every overlapped rebuilt cell
	CITA_MAPSIZE_TYPE value = cita_map_space_value(addr_end - addr);
	for (size_t im = gap_im0; im <= gap_im1; im++)
		if (value > map[im].free_space)
			map[im].free_space = value;
}

void cita_map_rebuild_free_spaces(cita_map_cell_t *map, size_t im0, size_t im1, CITA_INDEX_TYPE gap_index, CITA_ADDR_TYPE rebuild_start, CITA_ADDR_TYPE rebuild_end)
{
	// Walk each linked gap once to rebuild free-space values
	#ifdef CITA_GAP_LINKS
	gap_index = cita_gap_first_at_or_after(gap_index);
	#endif
	while (gap_index != NAI)
	{
		cita_elem_t *el = &ct->elem[gap_index];
		if (el->next_index == 0)
			break;

		CITA_ADDR_TYPE addr = cita_align_up(el->addr_end);
		CITA_ADDR_TYPE addr_end = ct->elem[el->next_index].addr;
		if (addr < addr_end)
		{
			if (addr >= rebuild_end)
				break;
			if (addr_end > rebuild_start)
				cita_map_store_free_space(map, im0, im1, addr, addr_end);
		}

		#ifdef CITA_GAP_LINKS
		gap_index = cita_gap_next_linked(gap_index);
		#else
		gap_index = el->next_index;
		#endif
	}
}

CITA_INDEX_TYPE cita_map_find_free_space(CITA_ADDR_TYPE required_space)
{
	if (!cita_map_ready)
		return NAI;

	// Make sure the map covers the current heap before searching it
	cita_map_ensure_capacity();

	CITA_MAPSIZE_TYPE required_value = cita_map_space_value(required_space);
	cita_map_cell_t *map = CITA_PTR(ct->elem[2].addr);

	// Search map cells for a reusable free space that may be large enough
	for (size_t im = 0; im < cita_map_count; im++)
		if (map[im].free_space >= required_value)
		{
			CITA_ADDR_TYPE cell_start, cell_end;
			cita_map_cell_range(im, &cell_start, &cell_end);

			// Check the linked free spaces around the promising cell
			CITA_INDEX_TYPE index = cita_map_find_rebuild_start(map, im, im, cell_start);
			CITA_INDEX_TYPE gap_index = cita_map_next_gap_index(cita_map_find_gap_start(index), cell_start);
			while (gap_index != NAI)
			{
				CITA_ADDR_TYPE addr, addr_end;
				if (cita_free_space_after(gap_index, &addr, &addr_end))
				{
					if (addr >= cell_end)
						break;
					if (cell_start < addr_end && addr_end - addr >= required_space)
						return gap_index;
				}

				#ifdef CITA_GAP_LINKS
				gap_index = cita_gap_next_linked(gap_index);
				#else
				if (ct->elem[gap_index].next_index == 0)
					break;
				gap_index = ct->elem[gap_index].next_index;
				#endif
			}
		}

	return NAI;
}

void cita_map_rebuild_range(size_t im0, size_t im1)
{
	if (cita_map_update_skip)
		return;

	// Ensure the map is large enough for the current heap
	cita_map_ensure_capacity();

	// Validate the requested cell range
	if (im0 > im1 || cita_map_count == 0)
		return;
	if (im1 >= cita_map_count)
	{
		CITA_REPORT("cita_map_rebuild_range(%zd, %zd): map cell %zd is outside of the %zd allocated cells. Input info says \"%s\"", im0, im1, im1, cita_map_count, cita_input_info);
		im1 = cita_map_count - 1;
	}

	// Find the first linked element that may overlap the rebuilt range
	cita_map_cell_t *map = CITA_PTR(ct->elem[2].addr);
	CITA_ADDR_TYPE rebuild_start = CITA_MEM_START + ((CITA_ADDR_TYPE) im0 << CITA_MAP_SCALE);
	CITA_INDEX_TYPE index = cita_map_find_rebuild_start(map, im0, im1, rebuild_start);
	CITA_INDEX_TYPE gap_index = cita_map_find_gap_start(index);
	CITA_ADDR_TYPE rebuild_last_start, rebuild_end;
	cita_map_cell_range(im1, &rebuild_last_start, &rebuild_end);

	// Rebuild each affected map cell from linked elements in address order
	for (size_t im = im0; im <= im1; im++)
	{
		// Compute this cell's address range
		CITA_ADDR_TYPE cell_start, cell_end;
		cita_map_cell_range(im, &cell_start, &cell_end);

		// Clear the free-space entry before repainting linked gaps
		map[im].free_space = 0;

		// Keep the base marker in the first map cell
		if (im == 0)
		{
			map[im].index = 0;
		}
		else
		{
			// Store the first linked element that overlaps this cell
			index = cita_map_next_cell_index(index, cell_start);
			if (index && ct->elem[index].addr < cell_end)
				map[im].index = index;
			else
				map[im].index = NAI;
		}
	}

	// Store the biggest reusable free space that overlaps each rebuilt cell
	cita_map_rebuild_free_spaces(map, im0, im1, gap_index, rebuild_start, rebuild_end);
}

void cita_map_update_range(CITA_INDEX_TYPE index)
{
	if (cita_map_update_skip)
		return;

	// Include the element and adjacent free spaces in the rebuild range
	size_t im0 = 1, im1 = 0;
	if (index != 1 && index != 2)
	{
		cita_map_set_elem_range(index);
		cita_map_include_elem(&im0, &im1, index);
	}
	cita_map_include_free_space_after(&im0, &im1, ct->elem[index].prev_index);
	cita_map_include_free_space_after(&im0, &im1, index);

	cita_map_rebuild_range(im0, im1);
}
#endif

int32_t cita_table_find_buffer(CITA_ADDR_TYPE addr, const int start_only)
{
	CITA_INDEX_TYPE i = 0;

	// Basic address checks
	if (addr < CITA_MEM_START)
	{
		CITA_REPORT("cita_table_find_buffer(%#zx): pointer isn't a heap address, heap starts at %#zx. Input info says \"%s\"", (uintptr_t) addr, (uintptr_t) CITA_MEM_START, cita_input_info);
		return NAI;
	}

	if (addr >= CITA_MEM_END)
	{
		CITA_REPORT("cita_table_find_buffer(%#zx): pointer is outside of the memory which ends at %#zx. Input info says \"%s\"", (uintptr_t) addr, (uintptr_t) CITA_MEM_END, cita_input_info);
		return NAI;
	}

	#ifdef CITA_MAP_SCALE

	CITA_INDEX_TYPE i_starting = i;

	if (cita_map_ready)
	{
		// Find a starting index from the map
		cita_map_cell_t *map = CITA_PTR(ct->elem[2].addr);
		size_t im = (addr - CITA_MEM_START) >> CITA_MAP_SCALE;
		i = im < cita_map_count ? map[im].index : NAI;
		i_starting = i;

		// If the map index is unusable, start from the last range
		if (i == NAI || i >= ct->elem_count || ct->elem[i].next_index == NAI)
			i = ct->elem[0].prev_index;
	}

	#endif

	CITA_INDEX_TYPE i1 = NAI, i2 = NAI;

	// Traverse the table in linked order to find the buffer address
	do
	{
		cita_elem_t *el = &ct->elem[i];

		// Check if the address is inside the range
		if (el->addr <= addr && addr < el->addr_end)
		{
			if (el->addr == addr || start_only == 0)
			{
				#ifdef CITA_MAP_SCALE
				// Update the map for this range if needed
				if (i != i_starting)
					cita_map_update_range(i);
				#endif

				// Return index
				return i;
			}

			#if CITA_INFO_LEN > 0
			CITA_REPORT("cita_table_find_buffer(%#zx): pointer points to inside the buffer starting %zd (%#zx) bytes earlier at %#zx. Buffer is up to %zd (%#zx) bytes large and has this info: \"%.*s\". Input info says \"%s\"", (uintptr_t) addr, (uintptr_t) addr-el->addr, (uintptr_t) addr-el->addr, (uintptr_t) el->addr, (uintptr_t) el->addr_end-el->addr, (uintptr_t) el->addr_end-el->addr, (int) sizeof(el->extra.info), el->extra.info, cita_input_info);
			#else
			CITA_REPORT("cita_table_find_buffer(%#zx): pointer points to inside the buffer starting %zd (%#zx) bytes earlier at %#zx. Buffer is up to %zd (%#zx) bytes large. Input info says \"%s\"", (uintptr_t) addr, (uintptr_t) addr-el->addr, addr-el->addr, (uintptr_t) el->addr, (uintptr_t) el->addr_end-el->addr, (uintptr_t) el->addr_end-el->addr, cita_input_info);
			#endif
			return NAI;
		}

		// Keep track of previous two indices to check for addr being in an empty space
		if (i == i2)
			return NAI;
		i2 = i1;
		i1 = i;

		// Traverse in a direction that depends on which side of this range is the address
		if (addr < el->addr)
			i = el->prev_index;
		else
			i = el->next_index;
	}
	while (i);

	return NAI;
}

void cita_enlarge_memory(CITA_ADDR_TYPE req)
{
	CITA_ADDR_TYPE old_end = CITA_MEM_END;
	if (req > old_end)
		CITA_MEM_ENLARGE(req)
	else
		return;

	// Report failure to enlarge by enough
	if (req > CITA_MEM_END)
		CITA_REPORT("cita_enlarge_memory(): requested increase from %#zx (%.1f MB) to at least %#zx (%.1f MB) but the memory can only be enlarged to %#zx (%.1f MB). Input info says \"%s\"", (uintptr_t) old_end, old_end/1048576., (uintptr_t) req, req/1048576., CITA_MEM_END, CITA_MEM_END/1048576., cita_input_info);

	// Erase new range
	cita_erase_to_mem_end(old_end);

	#ifdef CITA_MAP_SCALE
	// Enlarge map
	cita_map_ensure_capacity();
	#endif
}

#ifdef CITA_ALWAYS_CHECK_LINKS
int cita_check_links(const char *func, int line)
{
	int32_t ir;

	// Go through each link to make sure they point to each other
	for (ir=0; ir < ct->elem_count; ir++)
		if (ct->elem[ir].next_index != NAI)
		{
			if (ct->elem[ct->elem[ir].next_index].prev_index != ir)
				CITA_REPORT("cita_check_links(%s:%d) elem[%d].next_index = %d but elem[%d].prev_index = %d. Input info says \"%s\"", func, line, ir, ct->elem[ir].next_index, ct->elem[ir].next_index, ct->elem[ct->elem[ir].next_index].prev_index, cita_input_info);

			if (ct->elem[ct->elem[ir].prev_index].next_index != ir)
				CITA_REPORT("cita_check_links(%s:%d) elem[%d].prev_index = %d but elem[%d].next_index = %d. Input info says \"%s\"", func, line, ir, ct->elem[ir].prev_index, ct->elem[ir].prev_index, ct->elem[ct->elem[ir].prev_index].next_index, cita_input_info);
		}

	// Go through the chain and mark each element
	for (ir=0; ct->elem[ir].extra.link == 0; ir = ct->elem[ir].next_index)
		ct->elem[ir].extra.link++;

	// Go through each element to see if any weren't marked
	int unmarked_count = 0;
	for (ir=0; ir < ct->elem_count; ir++)
	{
		if (ct->elem[ir].next_index != NAI && ct->elem[ir].extra.link != 1)
		{
			unmarked_count++;
			CITA_PRINT("cita_check_links(): elem[%d] is unlinked, prev %d next %d", ir, ct->elem[ir].prev_index, ct->elem[ir].next_index);
		}
		ct->elem[ir].extra.link = 0;
	}

	#ifdef CITA_GAP_LINKS
	// Go through each linked element to validate gap-run hints
	int gap_error_count = 0;
	for (ir=0; ir < ct->elem_count; ir++)
		if (ct->elem[ir].next_index != NAI)
		{
			CITA_INDEX_TYPE expected_prev_gap_index = cita_gap_span_start((CITA_INDEX_TYPE) ir);
			CITA_INDEX_TYPE expected_next_gap_index = cita_gap_span_end((CITA_INDEX_TYPE) ir);

			if (ct->elem[ir].prev_gap_index != expected_prev_gap_index || ct->elem[ir].next_gap_index != expected_next_gap_index)
			{
				gap_error_count++;
				CITA_PRINT("cita_check_links(): elem[%d] gap links are prev %llu next %llu but expected prev %llu next %llu", ir, (unsigned long long) ct->elem[ir].prev_gap_index, (unsigned long long) ct->elem[ir].next_gap_index, (unsigned long long) expected_prev_gap_index, (unsigned long long) expected_next_gap_index);
			}
		}

	// Report gap-owner link anomalies
	if (gap_error_count)
		CITA_REPORT("cita_check_links(%s:%d) found %d gap-owner link errors. Input info says \"%s\"", func, line, gap_error_count, cita_input_info);
	#endif

	// Report anomalies
	if (unmarked_count)
		CITA_REPORT("cita_check_links(%s:%d) found %d unlinked elements. Input info says \"%s\"", func, line, unmarked_count, cita_input_info);
	return unmarked_count;
}
#endif

int cita_check_links_internal(const char *func, int line)
{
#ifdef CITA_ALWAYS_CHECK_LINKS
	return cita_check_links(func, line);
#endif
	return 0;
}

void cita_table_init()
{
	if (ct)
		return;

	// Enlarge memory if needed
	cita_enlarge_memory(CITA_MEM_START + sizeof(cita_table_t));

	// Erase whole heap
	cita_erase_to_mem_end(CITA_MEM_START);

	// Allocate table structure
	ct = CITA_PTR(CITA_MEM_START);

	// Write signature and version so the host knows it's CIT Alloc
	memcpy(ct->cita_signature, "CITA", 4);

	// Write version for the viewer to be able to parse the table
	ct->version_offset = ct->cita_version - ct->cita_signature;
	int iv = 0;
	memcpy(&ct->cita_version[iv], "CITA 1.0\nAddress ", 17);		iv += 17;
	ct->cita_version[iv] = '0' + sizeof(CITA_ADDR_TYPE);			iv += 1;
	memcpy(&ct->cita_version[iv], "\nIndex ", 7);				iv += 7;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->prev_index);		iv += 1;

	#ifdef CITA_GAP_LINKS
	memcpy(&ct->cita_version[iv], "\nGap index ", 11);			iv += 11;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->prev_gap_index);		iv += 1;
	#endif

	#ifdef CITA_MAP_SCALE
	memcpy(&ct->cita_version[iv], "\nMap index ", 11);			iv += 11;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->map_start);		iv += 1;
	memcpy(&ct->cita_version[iv], "\nMap space ", 11);			iv += 11;
	ct->cita_version[iv] = '0' + sizeof(((cita_map_cell_t *) 0)->free_space);	iv += 1;
	#endif

	#ifndef CITA_EXCL_TIME
	memcpy(&ct->cita_version[iv], "\nTime ", 6);				iv += 6;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->extra.time_created);	iv += 1;
	#endif

	#ifdef CITA_ALWAYS_CHECK_LINKS
	memcpy(&ct->cita_version[iv], "\nLink ", 6);				iv += 6;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->extra.link);		iv += 1;
	#endif

	#if CITA_INFO_LEN > 0
	memcpy(&ct->cita_version[iv], "\nInfo ", 6);				iv += 6;
	size_t s = sizeof(ct->elem->extra.info);
	if (s / 100) { ct->cita_version[iv] = '0' + s / 100; s %= 100;		iv += 1; }
	if (s / 10)  { ct->cita_version[iv] = '0' + s / 10;  s %= 10;		iv += 1; }
	ct->cita_version[iv] = '0' + s;						iv += 1;
	#endif
	ct->cita_version[iv] = '\0';						iv += 1;

	// Compute the actual size of the written table header
	size_t cita_table_size = (size_t) ct->version_offset + (size_t) iv;

	cita_inc_event_counter();

	// Indicate that there's no available element
	ct->available_index = NAI;

	// Alloc table
	ct->elem = CITA_PTR(cita_align_up(CITA_ADDR(ct) + cita_table_size));
	ct->elem_count = 1;
	ct->elem_as = CITA_INIT_ELEM_AS;

	// Enlarge memory if needed
	CITA_ADDR_TYPE table_end = CITA_ADDR(&ct->elem[ct->elem_as]);
	cita_enlarge_memory(table_end);

	// Add elem 0 that represents the start of the memory and the table structure that never moves
	cita_elem_t *el = &ct->elem[0];
	el->prev_index = el->next_index = 0;
	#ifdef CITA_GAP_LINKS
	el->prev_gap_index = el->next_gap_index = 0;
	#endif
	el->addr = CITA_ADDR(ct);
	el->addr_end = CITA_ADDR(ct) + cita_table_size;
	#ifdef CITA_MAP_SCALE
	ct->elem[0].map_start = 0;
	ct->elem[0].map_end = 0;
	#endif
	#ifdef CITA_ALWAYS_CHECK_LINKS
	el->extra.link = 0;
	#endif
	#if CITA_INFO_LEN > 0
	strncpy(el->extra.info, "CITA base", sizeof(el->extra.info));
	#endif
	#ifndef CITA_EXCL_TIME
	el->extra.time_created = el->extra.time_modified = ct->timestamp;
	#endif

	// Add elem 1 which will always be the table
	char *orig_info = cita_input_info;
	cita_input_info = "CITA table";
	(void) cita_malloc(sizeof(cita_elem_t) * ct->elem_as);
	cita_input_info = orig_info;

	#ifdef CITA_MAP_SCALE
	// Add elem 2 which will always be the map
	orig_info = cita_input_info;
	cita_input_info = "CITA map";
	cita_map_count = CITA_MAP_COUNT_MIN;
	(void) cita_malloc(cita_map_count * sizeof(cita_map_cell_t));
	cita_input_info = orig_info;

	// Initialise the current state of the map
	cita_map_cell_t *map = CITA_PTR(ct->elem[2].addr);
	cita_map_init_cells(map, 0, cita_map_count - 1);
	map[0].index = 0;

	cita_map_ready = 1;
	cita_map_update_skip = 0;
	cita_map_ensure_capacity();

	// Rebuild the initial map cells around the internal allocations
	size_t im0 = 1, im1 = 0;
	cita_map_include_elem(&im0, &im1, 0);
	cita_map_include_elem(&im0, &im1, 1);
	cita_map_include_elem(&im0, &im1, 2);
	cita_map_include_free_space_after(&im0, &im1, 0);
	cita_map_include_free_space_after(&im0, &im1, 1);
	cita_map_include_free_space_after(&im0, &im1, 2);
	cita_map_rebuild_range(im0, im1);
	#endif
}

void cita_free_core(void *ptr, int allow_memset, int32_t index)
{
	cita_inc_event_counter();
	cita_check_links_internal(__func__, __LINE__);
	CITA_ADDR_TYPE addr = CITA_ADDR(ptr);

	if (ptr == NULL)
		return;

	// Find the table index of the buffer to free
	if (index == NAI)
		index = cita_table_find_buffer(addr, 1);

	// If the buffer wasn't found there's something wrong
	if (index == NAI)
	{
		index = cita_table_find_buffer(addr, 1);	// added for debugging convenience
		CITA_REPORT("cita_free(%#zx): buffer not found. Input info says \"%s\"", (uintptr_t) addr, cita_input_info);
		return;
	}

	cita_elem_t *el = &ct->elem[index];

	#ifdef CITA_MAP_SCALE
	size_t map_im0, map_im1;
	map_im0 = 1;
	map_im1 = 0;
	cita_map_include_elem(&map_im0, &map_im1, index);
	cita_map_include_free_space_after(&map_im0, &map_im1, el->prev_index);
	cita_map_include_free_space_after(&map_im0, &map_im1, index);
	#endif

	// Optionally erase the buffer data with a pattern
	#ifdef CITA_FREE_PATTERN
	if (allow_memset)
		memset(CITA_PTR(el->addr), CITA_FREE_PATTERN, el->addr_end - el->addr);
	#endif

	// Link the linked elements together
	#ifdef CITA_MAP_SCALE
	CITA_INDEX_TYPE prev_index = el->prev_index;
	#endif
	#ifdef CITA_GAP_LINKS
	CITA_INDEX_TYPE gap_prev_index = el->prev_index;
	cita_gap_unlink(index);
	#endif
	ct->elem[el->prev_index].next_index = el->next_index;
	ct->elem[el->next_index].prev_index = el->prev_index;

	// Indicate availability and link to the previous available element
	el->addr = el->addr_end = 0;
	el->next_index = NAI;
	el->prev_index = ct->available_index;
	#ifdef CITA_GAP_LINKS
	cita_gap_init_elem(index);
	cita_gap_refresh(gap_prev_index);
	#endif
	ct->available_index = index;
	#ifndef CITA_EXCL_TIME
	el->extra.time_modified = ct->timestamp;
	#endif

	#ifdef CITA_MAP_SCALE
	el->map_start = CITA_MAP_INDEX_NAI;
	el->map_end = 0;
	cita_map_include_free_space_after(&map_im0, &map_im1, prev_index);
	cita_map_rebuild_range(map_im0, map_im1);
	#endif

	cita_check_links_internal(__func__, __LINE__);
}

void cita_free(void *ptr)
{
	cita_free_core(ptr, 1, NAI);
}

int32_t cita_last_malloc_index = NAI;

void *cita_malloc(size_t size)
{
	cita_table_init();
	cita_inc_event_counter();
	cita_check_links_internal(__func__, __LINE__);

	// Check valid size
	if (size == 0)
	{
		CITA_REPORT("cita_malloc(%zd). Zero byte size requested. Input info says \"%s\"", size, cita_input_info);
		size = 1;
	}

	int32_t index = ct->available_index;

	// Get a table element
	if (index == NAI)
	{
		// Enlarge the table
		while (ct->elem_count+3 > ct->elem_as && ct->elem_as < NAI)
		{
			ct->elem_as *= 2;
			if (ct->elem_as > NAI)
				ct->elem_as = NAI;
			ct->elem = cita_realloc(ct->elem, ct->elem_as * sizeof(cita_elem_t));
		}
		ct->elem_count++;
		
		if (ct->elem_count > NAI)
			CITA_REPORT("cita_malloc(%zd). The number of elements in the table has reached the maximum. Use a larger index type. Input info says \"%s\"", size, cita_input_info);

		// Last element is now available, initialise it as such
		index = ct->elem_count - 1;
		ct->elem[index].prev_index = ct->available_index;
		ct->elem[index].next_index = NAI;
		#ifdef CITA_GAP_LINKS
		cita_gap_init_elem(index);
		#endif
		ct->elem[index].addr = ct->elem[index].addr_end = 0;
		ct->available_index = index;
	}

	cita_elem_t *el = &ct->elem[index];

	// Update available index
	ct->available_index = el->prev_index;
	el->prev_index = NAI;

	CITA_ADDR_TYPE required_space = size + CITA_PADDING;
	#ifdef CITA_MAP_SCALE
	// Search the map for a free space large enough
	CITA_INDEX_TYPE i = cita_map_find_free_space(required_space);
	if (i != NAI)
	{
		el->prev_index = i;
		el->next_index = ct->elem[el->prev_index].next_index;
	}
	#else
	#ifdef CITA_GAP_LINKS
	// Search linked gap owners for a free space large enough
	CITA_INDEX_TYPE i = cita_gap_find_free_space(required_space);
	if (i != NAI)
	{
		el->prev_index = i;
		el->next_index = ct->elem[el->prev_index].next_index;
	}
	#else
	// Traverse the table in linked order to find the first free space large enough
	CITA_INDEX_TYPE i = 0;
	do
	{
		if (cita_range_after_space(i) >= required_space)
		{
			el->prev_index = i;
			el->next_index = ct->elem[el->prev_index].next_index;
			break;
		}

		i = ct->elem[i].next_index;
	}
	while (i);
	#endif
	#endif

	// Get memory from the end if no suitable space was found
	if (el->prev_index == NAI)
	{
		// New element is added after the last one
		el->prev_index = ct->elem[0].prev_index;
		el->next_index = 0;
	}

	// Write the element
	el->addr = cita_align_up(ct->elem[el->prev_index].addr_end);	// address of buffer
	el->addr_end = el->addr + size;					// address after the end of this buffer
	#ifndef CITA_EXCL_TIME
	el->extra.time_created = el->extra.time_modified = ct->timestamp;
	#endif
	#ifdef CITA_ALWAYS_CHECK_LINKS
	el->extra.link = 0;
	#endif
	#if CITA_INFO_LEN > 0
	memset(el->extra.info, 0, sizeof(el->extra.info));
	if (cita_input_info)						// Extra info provided through a global pointer
		strncpy(el->extra.info, cita_input_info, sizeof(el->extra.info));
	#endif

	// Insert our element in the chain
	ct->elem[el->prev_index].next_index = index;
	ct->elem[el->next_index].prev_index = index;

	#ifdef CITA_GAP_LINKS
	// Update gap links around the inserted element
	cita_gap_refresh(index);
	cita_gap_refresh(el->prev_index);
	#endif

	// If the buffer is added at the end of the memory
	if (el->next_index == 0)
	{
		// Enlarge memory if needed
		CITA_ADDR_TYPE req = el->addr_end;
		cita_enlarge_memory(req);
		el = &ct->elem[index];

		// Report failure to obtain enough 
		if (el->addr_end > CITA_MEM_END)
		{
			CITA_REPORT("cita_malloc(%zd): new buffer would start at %#zx and end at %#zx (%.1f MB) but the memory can only be enlarged to %#zx (%.1f MB). Input info says \"%s\"", size, (uintptr_t) el->addr, (uintptr_t) el->addr_end, el->addr_end/1048576., (uintptr_t) CITA_MEM_END, (CITA_MEM_END-CITA_MEM_START)/1048576., cita_input_info);
			cita_free(CITA_PTR(el->addr));
			return NULL;
		}
	}

	#ifdef CITA_MAP_SCALE
	ct->elem[index].map_start = CITA_MAP_INDEX_NAI;
	ct->elem[index].map_end = 0;
	if (ct->elem_count > 3)
		cita_map_update_range(index);
	el = &ct->elem[index];
	#endif

	cita_check_links_internal(__func__, __LINE__);
	cita_last_malloc_index = index;

	return CITA_PTR(el->addr);
}

void *cita_calloc(size_t nmemb, size_t size)
{
	void *ptr = cita_malloc(nmemb*size);
	memset(ptr, 0, nmemb*size);
	return ptr;
}

void *cita_realloc(void *ptr, size_t size)
{
	CITA_ADDR_TYPE addr = CITA_ADDR(ptr);

	cita_table_init();
	cita_inc_event_counter();
	cita_check_links_internal(__func__, __LINE__);

	if (ptr == NULL)
		return cita_malloc(size);
	
	if (size == 0)
	{
		cita_free(ptr);
		return NULL;
	}

	// Find the table index of the buffer to free
	int32_t index = cita_table_find_buffer(addr, 1);
	if (index == NAI)
	{
		CITA_REPORT("cita_realloc(%#zx, %zd): buffer not found. Input info says \"%s\"", (uintptr_t) addr, size, cita_input_info);
		return NULL;
	}

	cita_elem_t *el = &ct->elem[index];

	// Check space from the start of this buffer to next buffer to see if there's already enough room
	CITA_ADDR_TYPE space = ct->elem[el->next_index].addr - el->addr;
	if (el->next_index == 0)	// if this buffer is at the end
	{
		// Enlarge memory if needed
		if (el->addr + size > CITA_MEM_END)
		{
			cita_enlarge_memory(el->addr + size);
			el = &ct->elem[index];
		}

		space = CITA_MEM_END - el->addr;
	}

	// If there's enough room, update the end of the buffer as well as the size of the space after it
	if (space >= size + CITA_PADDING)
	{
		#ifdef CITA_MAP_SCALE
		size_t map_im0, map_im1;
		map_im0 = 1;
		map_im1 = 0;
		cita_map_include_elem(&map_im0, &map_im1, index);
		cita_map_include_free_space_after(&map_im0, &map_im1, index);
		#endif

		el->addr_end = el->addr + size;
		#ifdef CITA_GAP_LINKS
		cita_gap_refresh(index);
		#endif
		#ifdef CITA_MAP_SCALE
		cita_map_set_elem_range(index);
		cita_map_include_elem(&map_im0, &map_im1, index);
		cita_map_include_free_space_after(&map_im0, &map_im1, index);
		cita_map_rebuild_range(map_im0, map_im1);
		el = &ct->elem[index];
		#endif
	}
	else
	{
		cita_elem_t el_copy = *el;
		#ifdef CITA_MAP_SCALE
		size_t old_map_im0, old_map_im1;
		old_map_im0 = 1;
		old_map_im1 = 0;
		cita_map_include_elem(&old_map_im0, &old_map_im1, index);
		cita_map_include_free_space_after(&old_map_im0, &old_map_im1, el->prev_index);
		cita_map_include_free_space_after(&old_map_im0, &old_map_im1, index);
		CITA_INDEX_TYPE old_table_prev_index = ct->elem[1].prev_index;
		CITA_ADDR_TYPE old_table_addr = ct->elem[1].addr;
		CITA_ADDR_TYPE old_table_addr_end = ct->elem[1].addr_end;
		#endif

		// Allocate new element to find a suitable address and trigger any map enlargement then free it
		int map_update_skip = cita_map_update_skip;
		cita_map_update_skip = 1;
		void *ptr_new = cita_malloc(size);
		if (ptr_new == NULL)
		{
			cita_map_update_skip = map_update_skip;
			return NULL;
		}
		cita_elem_t el_new_copy = ct->elem[cita_last_malloc_index];
		cita_free_core(ptr_new, 0, cita_last_malloc_index);
		cita_map_update_skip = map_update_skip;

		// Guard against the new buffer being linked to the old one
		if (el_new_copy.prev_index == index)
			el_new_copy.prev_index = el_copy.prev_index;
		if (el_new_copy.next_index == index)
			el_new_copy.next_index = el_copy.next_index;

		// Copy the data to the new location
		memcpy(ptr_new, ptr, el_copy.addr_end - el_copy.addr);

		// Update the elem pointer if moving the table
		if (index == 1)
			ct->elem = ptr_new;
		el = &ct->elem[index];

		// Remove our element from the old position in the chain
		#ifdef CITA_MAP_SCALE
		CITA_INDEX_TYPE old_prev_index = el->prev_index;
		#endif
		#ifdef CITA_GAP_LINKS
		CITA_INDEX_TYPE gap_old_prev_index = el->prev_index;
		cita_gap_unlink(index);
		#endif
		ct->elem[el->prev_index].next_index = el->next_index;
		ct->elem[el->next_index].prev_index = el->prev_index;
		#ifdef CITA_GAP_LINKS
		cita_gap_refresh(gap_old_prev_index);
		#endif
		#ifdef CITA_MAP_SCALE
		cita_map_include_free_space_after(&old_map_im0, &old_map_im1, old_prev_index);
		#endif

		// Update element addresses
		el->addr = el_new_copy.addr;
		el->addr_end = el_new_copy.addr_end;

		// Insert our element in the new position in the chain
		el->prev_index = el_new_copy.prev_index;
		el->next_index = el_new_copy.next_index;
		ct->elem[el->prev_index].next_index = index;
		ct->elem[el->next_index].prev_index = index;
		#ifdef CITA_GAP_LINKS
		cita_gap_refresh(index);
		cita_gap_refresh(el->prev_index);
		#endif

		// Erase the original data
		#ifdef CITA_FREE_PATTERN
		memset(ptr, CITA_FREE_PATTERN, el_copy.addr_end - el_copy.addr);
		#endif

		#ifndef CITA_EXCL_TIME
		el->extra.time_modified = ct->timestamp;
		#endif

		// Update map
		#ifdef CITA_MAP_SCALE
		cita_map_set_elem_range(index);
		cita_map_include_elem(&old_map_im0, &old_map_im1, index);
		cita_map_include_free_space_after(&old_map_im0, &old_map_im1, el->prev_index);
		cita_map_include_free_space_after(&old_map_im0, &old_map_im1, index);
		if (old_table_prev_index != ct->elem[1].prev_index || old_table_addr != ct->elem[1].addr || old_table_addr_end != ct->elem[1].addr_end)
			cita_map_include_moved_elem(&old_map_im0, &old_map_im1, 1, old_table_prev_index, old_table_addr, old_table_addr_end);
		cita_map_rebuild_range(old_map_im0, old_map_im1);
		el = &ct->elem[index];
		#endif
	}

	cita_check_links_internal(__func__, __LINE__);
	return CITA_PTR(el->addr);
}

CITA_ADDR_TYPE cita_find_end_addr()
{
	return ct->elem[ ct->elem[0].prev_index ].addr_end;
}

#undef ct
#endif // CITA_IMPLEMENTATION
