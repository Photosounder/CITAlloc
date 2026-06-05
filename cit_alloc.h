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
	CITA_ADDR_TYPE addr, addr_end;
	#ifdef CITA_MAP_SCALE
	CITA_MAPINDEX_TYPE map_start, map_end;
	#endif
	cita_extra_t extra;
} cita_elem_t;
#pragma pack(pop)

typedef struct
{
	char cita_signature[4];
	int32_t version_offset, available_index;
	volatile int32_t timestamp;	// meant to be updated by the host
	cita_elem_t *elem;
	size_t elem_count, elem_as;
	char cita_version[52];
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

CITA_ADDR_TYPE cita_range_after_space(CITA_INDEX_TYPE index)
{
	cita_elem_t *el = &ct->elem[index];
	return ct->elem[index].next_index ? ct->elem[el->next_index].addr - cita_align_up(ct->elem[index].addr_end) : 0;
}

void cita_erase_to_mem_end(CITA_ADDR_TYPE start)
{
	#ifdef CITA_FREE_PATTERN
	if (start < CITA_MEM_END)
		memset(CITA_PTR(start), CITA_FREE_PATTERN, CITA_MEM_END - start);
	#endif
}

int cita_map_update_skip = 1;
#ifdef CITA_MAP_SCALE
size_t cita_map_count = 0;
int8_t cita_map_ready = 0, cita_map_resizing = 0;

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

		int update_skip = cita_map_update_skip;
		cita_map_update_skip = 1;
		cita_map_resizing = 1;
		void *map_ptr = cita_realloc(CITA_PTR(ct->elem[2].addr), new_count * sizeof(CITA_INDEX_TYPE));
		cita_map_resizing = 0;
		cita_map_update_skip = update_skip;

		if (map_ptr == NULL)
		{
			CITA_REPORT("cita_map_ensure_capacity(): failed to enlarge map from %zd to %zd cells. Input info says \"%s\"", old_count, new_count, cita_input_info);
			return;
		}

		cita_map_count = new_count;
		CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
		memset(&map[old_count], 0xFF, (new_count - old_count) * sizeof(CITA_INDEX_TYPE));
	}
}

void cita_map_elem_cells(CITA_INDEX_TYPE index, size_t *im0, size_t *im1)
{
	cita_elem_t *el = &ct->elem[index];
	if (el->addr_end <= el->addr)
	{
		*im0 = 1;
		*im1 = 0;
		return;
	}

	*im0 = (el->addr       - CITA_MEM_START) >> CITA_MAP_SCALE;
	*im1 = (el->addr_end-1 - CITA_MEM_START) >> CITA_MAP_SCALE;
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

void cita_map_rebuild_range(size_t im0, size_t im1)
{
	if (cita_map_update_skip)
		return;

	cita_map_ensure_capacity();

	if (im0 > im1 || cita_map_count == 0)
		return;
	if (im1 >= cita_map_count)
	{
		CITA_REPORT("cita_map_rebuild_range(%zd, %zd): map cell %zd is outside of the %zd allocated cells. Input info says \"%s\"", im0, im1, im1, cita_map_count, cita_input_info);
		im1 = cita_map_count - 1;
	}

	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
	memset(&map[im0], 0xFF, (im1+1 - im0) * sizeof(CITA_INDEX_TYPE));

	CITA_INDEX_TYPE index = 0;
	do
	{
		if (index != 1 && index != 2)	// avoid directly referencing the table and the map in the map
		{
			size_t el_im0, el_im1;
			cita_map_elem_cells(index, &el_im0, &el_im1);

			if (el_im0 <= im1 && im0 <= el_im1)
			{
				size_t im_start = el_im0 > im0 ? el_im0 : im0;
				size_t im_end = el_im1 < im1 ? el_im1 : im1;
				for (size_t im = im_start; im <= im_end; im++)
					if (map[im] == NAI)
						map[im] = index;
			}
		}

		index = ct->elem[index].next_index;
	}
	while (index);
}

void cita_map_update_range(CITA_INDEX_TYPE index)
{
	if (cita_map_update_skip)
		return;

	CITA_INDEX_TYPE ii = index;
	while (ii == 1 || ii == 2)	// avoid directly referencing the table and the map in the map
		ii = ct->elem[ii].prev_index;

	cita_map_set_elem_range(ii);
	cita_map_rebuild_range(ct->elem[ii].map_start, ct->elem[ii].map_end);
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
		CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
		size_t im = (addr - CITA_MEM_START) >> CITA_MAP_SCALE;
		i = im < cita_map_count ? map[im] : NAI;
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

	#ifdef CITA_MAP_SCALE
	memcpy(&ct->cita_version[iv], "\nMap index ", 11);			iv += 11;
	ct->cita_version[iv] = '0' + sizeof(ct->elem->map_start);		iv += 1;
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
	ct->cita_version[iv] = '\0';						/*iv += 1;*/
	#endif

	cita_inc_event_counter();

	// Indicate that there's no available element
	ct->available_index = NAI;

	// Alloc table
	ct->elem = CITA_PTR(cita_align_up(CITA_ADDR(ct) + sizeof(cita_table_t)));
	ct->elem_count = 1;
	ct->elem_as = CITA_INIT_ELEM_AS;

	// Enlarge memory if needed
	CITA_ADDR_TYPE table_end = CITA_ADDR(&ct->elem[ct->elem_as]);
	cita_enlarge_memory(table_end);

	// Add elem 0 that represents the start of the memory and the table structure that never moves
	cita_elem_t *el = &ct->elem[0];
	el->prev_index = el->next_index = 0;
	el->addr = CITA_ADDR(ct);
	el->addr_end = CITA_ADDR(ct) + sizeof(cita_table_t);
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
	(void) cita_malloc(cita_map_count * sizeof(CITA_INDEX_TYPE));
	cita_input_info = orig_info;

	// Initialise the current state of the map
	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
	memset(map, 0xFF, ct->elem[2].addr_end - ct->elem[2].addr);	// NAI
	map[0] = 0;

	cita_map_ready = 1;
	cita_map_update_skip = 0;
	cita_map_ensure_capacity();
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
	cita_map_elem_cells(index, &map_im0, &map_im1);
	#endif

	// Optionally erase the buffer data with a pattern
	#ifdef CITA_FREE_PATTERN
	if (allow_memset)
		memset(CITA_PTR(el->addr), CITA_FREE_PATTERN, el->addr_end - el->addr);
	#endif

	// Link the linked elements together
	ct->elem[el->prev_index].next_index = el->next_index;
	ct->elem[el->next_index].prev_index = el->prev_index;

	// Indicate availability and link to the previous available element
	el->addr = el->addr_end = 0;
	el->next_index = NAI;
	el->prev_index = ct->available_index;
	ct->available_index = index;
	#ifndef CITA_EXCL_TIME
	el->extra.time_modified = ct->timestamp;
	#endif

	#ifdef CITA_MAP_SCALE
	el->map_start = CITA_MAP_INDEX_NAI;
	el->map_end = 0;
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
		ct->elem[index].addr = ct->elem[index].addr_end = 0;
		ct->available_index = index;
	}

	cita_elem_t *el = &ct->elem[index];

	// Update available index
	ct->available_index = el->prev_index;
	el->prev_index = NAI;

#if 0
	// Traverse the table linearly to find the first free space large enough
	for (int32_t i=0; i < ct->elem_count; i++)
		if (cita_range_after_space(i) >= size + CITA_PADDING)
		{
			el->prev_index = i;
			el->next_index = ct->elem[el->prev_index].next_index;
			break;
		}
#else
	// Traverse the table in linked order to find the first free space large enough
	CITA_INDEX_TYPE i = 0;
	do
	{
		if (cita_range_after_space(i) >= size + CITA_PADDING)
		{
			el->prev_index = i;
			el->next_index = ct->elem[el->prev_index].next_index;
			break;
		}

		i = ct->elem[i].next_index;
	}
	while (i);
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
		cita_map_elem_cells(index, &map_im0, &map_im1);
		#endif

		el->addr_end = el->addr + size;
		#ifdef CITA_MAP_SCALE
		cita_map_set_elem_range(index);
		if (ct->elem[index].map_start != CITA_MAP_INDEX_NAI)
		{
			if ((size_t) ct->elem[index].map_start < map_im0)
				map_im0 = ct->elem[index].map_start;
			if ((size_t) ct->elem[index].map_end > map_im1)
				map_im1 = ct->elem[index].map_end;
		}
		cita_map_rebuild_range(map_im0, map_im1);
		el = &ct->elem[index];
		#endif
	}
	else
	{
		cita_elem_t el_copy = *el;
		#ifdef CITA_MAP_SCALE
		size_t old_map_im0, old_map_im1;
		cita_map_elem_cells(index, &old_map_im0, &old_map_im1);
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
		ct->elem[el->prev_index].next_index = el->next_index;
		ct->elem[el->next_index].prev_index = el->prev_index;

		// Update element addresses
		el->addr = el_new_copy.addr;
		el->addr_end = el_new_copy.addr_end;

		// Insert our element in the new position in the chain
		el->prev_index = el_new_copy.prev_index;
		el->next_index = el_new_copy.next_index;
		ct->elem[el->prev_index].next_index = index;
		ct->elem[el->next_index].prev_index = index;

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
		if (ct->elem[index].map_start != CITA_MAP_INDEX_NAI)
		{
			if ((size_t) ct->elem[index].map_start < old_map_im0)
				old_map_im0 = ct->elem[index].map_start;
			if ((size_t) ct->elem[index].map_end > old_map_im1)
				old_map_im1 = ct->elem[index].map_end;
		}
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
