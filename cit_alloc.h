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

#undef CITA_MAP_SCALE
#ifdef CITA_MAP_SCALE
  #define CITA_MAP_COUNT_MIN ((CITA_MEM_END-CITA_MEM_START + (1<<CITA_MAP_SCALE)-1) >> CITA_MAP_SCALE)
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

void cita_map_replace_index(CITA_INDEX_TYPE a, CITA_INDEX_TYPE b)
{
	if (cita_map_update_skip)
		return;

	CITA_MAPINDEX_TYPE i;
	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);

	// Replace map cells containing a with b
	for (i = ct->elem[a].map_start; i <= ct->elem[a].map_end; i++)
		if (map[i] == a)
			map[i] = b;

	// Update the map range for element b
	if (ct->elem[a].map_start < ct->elem[b].map_start)
		ct->elem[b].map_start = ct->elem[a].map_start;

	if (ct->elem[a].map_end > ct->elem[b].map_end)
		ct->elem[b].map_end = ct->elem[a].map_end;

	// Clear the map range for element a
	ct->elem[a].map_start = NAI;
	ct->elem[a].map_end = 0;
}

void cita_map_update_range(CITA_INDEX_TYPE index)
{
	CITA_MAPINDEX_TYPE im, im0 ,im1;
	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);

	if (cita_map_update_skip)
		return;

	CITA_INDEX_TYPE ii = index;
	while (ii == 1 || ii == 2)	// avoid directly referencing the table and the map in the map
		ii = ct->elem[ii].prev_index;
	cita_elem_t *el = &ct->elem[ii];

	// Write the index in the map for the whole range
	im0 = (el->addr       - CITA_MEM_START) >> CITA_MAP_SCALE;
	im1 = (el->addr_end-1 - CITA_MEM_START) >> CITA_MAP_SCALE;
	for (im = im0; im <= im1; im++)
		map[im] = ii;

	// Update map index range for the element
	if (im0 < el->map_start)
		el->map_start = im0;
	if (im1 > el->map_end)
		el->map_end = im1;
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

	// Find a starting index from the map
	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
	i = map[(addr - CITA_MEM_START) >> CITA_MAP_SCALE];
	CITA_INDEX_TYPE i_starting = i;

	// If the map index is NAI, start from the last range
	if (i == NAI)
		i = ct->elem[0].prev_index;

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
	if (cita_map_update_skip == 0 && cita_map_count < CITA_MAP_COUNT_MIN)
	{
		cita_map_count = CITA_MAP_COUNT_MIN * 2;
		cita_realloc(CITA_PTR(ct->elem[2].addr), cita_map_count * sizeof(CITA_INDEX_TYPE));

		// Init new section to NAI
		CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);
		CITA_MAPINDEX_TYPE im = (old_end - CITA_MEM_START) >> CITA_MAP_SCALE;
		memset(&map[im], 0xFF, (cita_map_count - im) * sizeof(CITA_INDEX_TYPE));
	}
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

	cita_map_update_skip = 0;
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

	// Remove from the map
	#ifdef CITA_MAP_SCALE
	cita_map_replace_index(index, el->prev_index);
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
		while (ct->elem_count+3 > ct->elem_as)
		{
			ct->elem_as *= 2;
			ct->elem = cita_realloc(ct->elem, ct->elem_as * sizeof(cita_elem_t));
		}
		ct->elem_count++;

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
		cita_enlarge_memory(el->addr_end);

		// Report failure to obtain enough 
		if (el->addr_end > CITA_MEM_END)
		{
			CITA_REPORT("cita_malloc(%zd): new buffer would start at %#zx and end at %#zx (%.1f MB) but the memory can only be enlarged to %#zx (%.1f MB). Input info says \"%s\"", size, (uintptr_t) el->addr, (uintptr_t) el->addr_end, el->addr_end/1048576., (uintptr_t) CITA_MEM_END, CITA_MEM_END/1048576., cita_input_info);
			cita_free(CITA_PTR(el->addr));
			return NULL;
		}
	}

	#ifdef CITA_MAP_SCALE
	ct->elem[index].map_start = NAI;
	ct->elem[index].map_end = 0;
	if (ct->elem_count > 3)
		cita_map_update_range(index);
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
			cita_enlarge_memory(el->addr + size);

		space = CITA_MEM_END - el->addr;
	}

	// If there's enough room, update the end of the buffer as well as the size of the space after it
	if (space >= size + CITA_PADDING)
	{
		CITA_ADDR_TYPE addr_after_old = el->addr_end;
		el->addr_end = el->addr + size;
	}
	else
	{
		cita_elem_t el_copy = *el;

		// Allocate new element to find a suitable address and trigger any map enlargement then free it
		cita_map_update_skip = 1;
		void *ptr_new = cita_malloc(size);
		cita_elem_t el_new_copy = ct->elem[cita_last_malloc_index];
		cita_free_core(ptr_new, 0, cita_last_malloc_index);
		cita_map_update_skip = 0;

		// Remove old index from the map
		#ifdef CITA_MAP_SCALE
		cita_map_replace_index(index, el_copy.prev_index);
		#endif

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
		el->map_start = NAI;
		el->map_end = 0;
		cita_map_update_range(index);
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
