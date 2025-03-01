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
- Not thread-safe for now because I don't need it to be.
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
CITA_PRINT(fmt, ...): A printf-like function to just print
CITA_REPORT(fmt, ...): A printf-like function to report serious
  errors by the caller

Optional:
CITA_MAP_SCALE: Enables the map and defines the power of 2 for the
  size of one cell of the map, e.g. 14 means a cell covers 16 kB.
CITA_FREE_PATTERN: A byte pattern, e.g. 0xE6, that if set will be
  used to erase all unused bytes between CITA_MEM_START and
  CITA_MEM_END
CITA_ALWAYS_CHECK_LINKS: All functions will check the integrity of
  the links between the table elements
CITA_EXCLUDE_STRING_H: To avoid including <string.h>
CITA_EXCL_TIME: Exclude timestamps from the info table

*/

#ifndef H_CITA
#define H_CITA

#include <stdint.h>

extern void *cita_malloc(size_t size);
extern void cita_free(void *ptr);
extern void *cita_calloc(size_t nmemb, size_t size);
extern void *cita_realloc(void *ptr, size_t size);

extern int32_t cita_table_find_buffer(size_t addr, int start_only);

extern char *cita_input_info;

#endif // H_CITA

#ifdef CITA_IMPLEMENTATION

#ifndef CITA_EXCLUDE_STRING_H
  #include <string.h>
#endif

// Not An Index
#define NAI ((CITA_INDEX_TYPE) -1)

#ifdef CITA_MAP_SCALE
  #define CITA_MAP_COUNT_MIN ((CITA_MEM_END-CITA_MEM_START + (1<<CITA_MAP_SCALE)-1) >> CITA_MAP_SCALE)
#endif

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
	size_t addr, addr_after, after_space;
	cita_extra_t extra;
} cita_elem_t;

typedef struct
{
	char cita_signature[4];
	int32_t version_offset, available_index;
	volatile int32_t timestamp;	// meant to be updated by the host
	cita_elem_t *elem;
	size_t elem_count, elem_as;
	char cita_version[52];
} cita_table_t;

cita_table_t *cita_table=NULL;
#define c cita_table
char *cita_input_info=NULL;
int cita_event_counter = 0;

size_t cita_align_down(size_t addr)
{
	return addr & ~(CITA_ALIGN-1);
}

size_t cita_align_up(size_t addr)
{
	return cita_align_down(addr+CITA_ALIGN-1);
}

void cita_erase_to_mem_end(size_t start)
{
	#ifdef CITA_FREE_PATTERN
	if (start < CITA_MEM_END)
		memset((void *) start, CITA_FREE_PATTERN, CITA_MEM_END - start);
	#endif
}

#ifdef CITA_MAP_SCALE
size_t cita_map_count = 0;
int8_t cita_map_update_skip = 0;

void cita_map_update_range(size_t addr, size_t addr_after)
{
	if (c->elem_count < 3 || cita_map_update_skip)
		return;

	CITA_INDEX_TYPE *map = (CITA_INDEX_TYPE *) c->elem[2].addr;

	// Determine the range in map cell indices
	size_t im0 = (addr         - CITA_MEM_START) >> CITA_MAP_SCALE;
	size_t im1 = (addr_after-1 - CITA_MEM_START) >> CITA_MAP_SCALE;

	// Set the whole range to NAI
	memset(&map[im0], 0xFF, (im1+1 - im0) * sizeof(CITA_INDEX_TYPE));
	if (im0 == 0)
	{
		im0 = 1;
		map[0] = 0;
	}

	// Start from the elem at the start of the previous non-NAI cell
	size_t ie = NAI;
	for (size_t im = im0 ? im0-1 : 0; ie == NAI; im--)
		ie = map[im];
	size_t im_min = im0;

	do
	{
		size_t range0 = (c->elem[ie].addr         - CITA_MEM_START) >> CITA_MAP_SCALE;
		size_t range1 = (c->elem[ie].addr_after-1 - CITA_MEM_START) >> CITA_MAP_SCALE;
		range0 = im_min > range0 ? im_min : range0;

		if (range0 > im1)
			return;

		// Set the elem's cell range to the elem's index
		for (size_t im = range0; im <= range1; im++)
			if (map[im] == NAI)
				map[im] = ie;

		im_min = range1;
		ie = c->elem[ie].next_index;
	}
	while (ie);
}
#endif

void cita_enlarge_memory(size_t req)
{
	size_t old_size = CITA_MEM_END;
	if (req > old_size)
		CITA_MEM_ENLARGE(req);
	else
		return;

	// Report failure to enlarge by enough
	if (req > CITA_MEM_END)
		CITA_REPORT("cita_enlarge_memory(): requested increase from %#zx (%.1f MB) to at least %#zx (%.1f MB) but the memory can only be enlarged to %#zx (%.1f MB)", old_size, old_size/1048576., req, req/1048576., CITA_MEM_END, CITA_MEM_END/1048576.);

	// Erase new range
	cita_erase_to_mem_end(old_size);

	#ifdef CITA_MAP_SCALE
	// Enlarge map
	if (cita_map_count < CITA_MAP_COUNT_MIN)
	{
		cita_map_count = CITA_MAP_COUNT_MIN * 2;
		cita_realloc((void *) c->elem[2].addr, cita_map_count * sizeof(CITA_INDEX_TYPE));

		// Init new section to NAI
		cita_map_update_range(CITA_MEM_START, CITA_MEM_END);
	}
	#endif
}

#ifdef CITA_ALWAYS_CHECK_LINKS
int cita_check_links(const char *func, int line)
{
	int32_t ir;

	// Go through each link to make sure they point to each other
	for (ir=0; ir < c->elem_count; ir++)
		if (c->elem[ir].next_index != NAI)
		{
			if (c->elem[c->elem[ir].next_index].prev_index != ir)
				CITA_REPORT("cita_check_links(%s:%d) elem[%d].next_index = %d but elem[%d].prev_index = %d", func, line, ir, c->elem[ir].next_index, c->elem[ir].next_index, c->elem[c->elem[ir].next_index].prev_index);

			if (c->elem[c->elem[ir].prev_index].next_index != ir)
				CITA_REPORT("cita_check_links(%s:%d) elem[%d].prev_index = %d but elem[%d].next_index = %d", func, line, ir, c->elem[ir].prev_index, c->elem[ir].prev_index, c->elem[c->elem[ir].prev_index].next_index);
		}

	// Go through the chain and mark each element
	for (ir=0; c->elem[ir].extra.link == 0; ir = c->elem[ir].next_index)
		c->elem[ir].extra.link++;

	// Go through each element to see if any weren't marked
	int unmarked_count = 0;
	for (ir=0; ir < c->elem_count; ir++)
	{
		if (c->elem[ir].next_index != NAI && c->elem[ir].extra.link != 1)
		{
			unmarked_count++;
			CITA_PRINT("cita_check_links(): elem[%d] is unlinked, prev %d next %d", ir, c->elem[ir].prev_index, c->elem[ir].next_index);
		}
		c->elem[ir].extra.link = 0;
	}

	// Report anomalies
	if (unmarked_count)
		CITA_REPORT("cita_check_links(%s:%d) found %d unlinked elements", func, line, unmarked_count);
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
	if (c)
		return;

	// Erase whole heap
	cita_erase_to_mem_end(CITA_MEM_START);

	// Allocate table structure
	c = (cita_table_t *) CITA_MEM_START;

	// Write signature and version so the host knows it's CIT Alloc
	memcpy(c->cita_signature, "CITA", 4);

	// Write version for the viewer to be able to parse the table
	c->version_offset = c->cita_version - c->cita_signature;
	int iv = 0;
	memcpy(&c->cita_version[iv], "CITA 1.0\nAddress ", 17);			iv += 17;
	c->cita_version[iv] = '0' + sizeof(size_t);				iv += 1;
	memcpy(&c->cita_version[iv], "\nIndex ", 7);				iv += 7;
	c->cita_version[iv] = '0' + sizeof(c->elem->prev_index);		iv += 1;

	#ifndef CITA_EXCL_TIME
	memcpy(&c->cita_version[iv], "\nTime ", 6);				iv += 6;
	c->cita_version[iv] = '0' + sizeof(c->elem->extra.time_created);	iv += 1;
	#endif

	#ifdef CITA_ALWAYS_CHECK_LINKS
	memcpy(&c->cita_version[iv], "\nLink ", 6);				iv += 6;
	c->cita_version[iv] = '0' + sizeof(c->elem->extra.link);		iv += 1;
	#endif

	#if CITA_INFO_LEN > 0
	memcpy(&c->cita_version[iv], "\nInfo ", 6);				iv += 6;
	size_t s = sizeof(c->elem->extra.info);
	if (s / 100) { c->cita_version[iv] = '0' + s / 100; s %= 100;		iv += 1; }
	if (s / 10)  { c->cita_version[iv] = '0' + s / 10;  s %= 10;		iv += 1; }
	c->cita_version[iv] = '0' + s;						iv += 1;
	c->cita_version[iv] = '\0';						iv += 1;
	#endif

	// Indicate that there's no available element
	c->available_index = NAI;

	// Alloc table
	c->elem = (cita_elem_t *) cita_align_up((size_t) c + sizeof(cita_table_t));
	c->elem_count = 1;
	c->elem_as = 16;	// can be changed

	// Enlarge memory if needed
	size_t table_end = (size_t) &c->elem[c->elem_as];
	cita_enlarge_memory(table_end);

	// Add elem 0 that represents the start of the memory and the table structure that never moves
	cita_elem_t *el = &c->elem[0];
	el->prev_index = el->next_index = 0;
	el->addr = (size_t) c;
	el->addr_after = (size_t) c->elem;
	el->after_space = 0;
	#ifdef CITA_ALWAYS_CHECK_LINKS
	el->extra.link = 0;
	#endif
	#if CITA_INFO_LEN > 0
	strncpy(el->extra.info, "CITA base", sizeof(el->extra.info));
	#endif
	#ifndef CITA_EXCL_TIME
	el->extra.time_created = el->extra.time_modified = c->timestamp;
	#endif

	// Add elem 1 which will always be the table
	char *orig_info = cita_input_info;
	cita_input_info = "CITA table";
	(void) cita_malloc(sizeof(cita_elem_t) * c->elem_as);
	cita_input_info = orig_info;

	#ifdef CITA_MAP_SCALE
	// Add elem 2 which will always be the map
	orig_info = cita_input_info;
	cita_input_info = "CITA map";
	cita_map_count = CITA_MAP_COUNT_MIN;
	(void) cita_malloc(cita_map_count * sizeof(CITA_INDEX_TYPE));
	cita_input_info = orig_info;

	// Initialise the current state of the map
	cita_map_update_range(CITA_MEM_START, CITA_MEM_END);
	#endif
}

int32_t cita_table_find_buffer(size_t addr, int start_only)
{
	int32_t i = 0;

	// Basic address checks
	if (addr < CITA_MEM_START)
	{
		CITA_REPORT("cita_table_find_buffer(%#zx): pointer isn't a heap address, heap starts at %#zx. Input info says \"%s\"", addr, CITA_MEM_START, cita_input_info);
		return NAI;
	}

	if (addr >= CITA_MEM_END)
	{
		CITA_REPORT("cita_table_find_buffer(%#zx): pointer is outside of the memory which ends at %#zx. Input info says \"%s\"", addr, CITA_MEM_END, cita_input_info);
		return NAI;
	}

	#ifdef CITA_MAP_SCALE
	// Find a starting index from the map
	CITA_INDEX_TYPE *map = (CITA_INDEX_TYPE *) c->elem[2].addr;
	i = map[(addr-CITA_MEM_START) >> CITA_MAP_SCALE];
	if (i == NAI)
		return NAI;
	#endif

	// Traverse the table in linked order to find the buffer address
	do
	{
		if (c->elem[i].addr <= addr && addr < c->elem[i].addr_after)
		{
			if (c->elem[i].addr == addr || start_only == 0)
				return i;

			#if CITA_INFO_LEN > 0
			CITA_REPORT("cita_table_find_buffer(%#zx): pointer points to inside the buffer starting %zd (%#zx) bytes earlier at %#zx. Buffer is up to %zd (%#zx) bytes large and has this info: \"%.*s\"", addr, addr-c->elem[i].addr, addr-c->elem[i].addr, c->elem[i].addr, c->elem[i].addr_after-c->elem[i].addr, c->elem[i].addr_after-c->elem[i].addr, (int) sizeof(c->elem[i].extra.info), c->elem[i].extra.info);
			#else
			CITA_REPORT("cita_table_find_buffer(%#zx): pointer points to inside the buffer starting %zd (%#zx) bytes earlier at %#zx. Buffer is up to %zd (%#zx) bytes large.", addr, addr-c->elem[i].addr, addr-c->elem[i].addr, c->elem[i].addr, c->elem[i].addr_after-c->elem[i].addr, c->elem[i].addr_after-c->elem[i].addr);
			#endif
			return NAI;
		}

		i = c->elem[i].next_index;
	}
	while (i);

	return NAI;
}

void cita_free_core(void *ptr, int allow_memset)
{
	cita_event_counter++;
	cita_check_links_internal(__func__, __LINE__);
	size_t addr = (size_t) ptr;

	if (ptr == NULL)
		return;

	// Find the table index of the buffer to free
	int32_t index = cita_table_find_buffer(addr, 1);
	if (index == NAI)
	{
		CITA_REPORT("cita_free(%#zx): buffer not found. Input info says \"%s\"", addr, cita_input_info);
		return;
	}

	cita_elem_t *el = &c->elem[index];

	#ifdef CITA_MAP_SCALE
	size_t addr_after = el->addr_after;
	#endif
	
	// Optionally erase the buffer data with a pattern
	#ifdef CITA_FREE_PATTERN
	if (allow_memset)
		memset((void *) el->addr, CITA_FREE_PATTERN, el->addr_after - el->addr);
	#endif

	// Link the linked elements together
	c->elem[el->prev_index].next_index = el->next_index;
	c->elem[el->next_index].prev_index = el->prev_index;

	// Update the size of the free space
	c->elem[el->prev_index].after_space = el->next_index ? c->elem[el->next_index].addr - c->elem[el->prev_index].addr_after : 0;

	// Indicate availability and link to the previous available element
	el->addr = el->addr_after = el->after_space = 0;
	el->next_index = NAI;
	el->prev_index = c->available_index;
	c->available_index = index;
	#ifndef CITA_EXCL_TIME
	el->extra.time_modified = c->timestamp;
	#endif

	#ifdef CITA_MAP_SCALE
	cita_map_update_range(addr, addr_after);
	#endif

	cita_check_links_internal(__func__, __LINE__);
}

void cita_free(void *ptr)
{
	cita_free_core(ptr, 1);
}

void *cita_malloc(size_t size)
{
	cita_table_init();
	cita_event_counter++;
	cita_check_links_internal(__func__, __LINE__);

	int32_t index = c->available_index;

	// Get a table element
	if (index == NAI)
	{
		// Enlarge the table
		if (c->elem_count+1 > c->elem_as)
		{
			c->elem_as *= 2;
			c->elem = cita_realloc(c->elem, c->elem_as * sizeof(cita_elem_t));
		}
		c->elem_count++;

		// Last element is now available, initialise it as such
		index = c->elem_count - 1;
		c->elem[index].prev_index = c->available_index;
		c->elem[index].next_index = NAI;
		c->elem[index].addr = c->elem[index].addr_after = c->elem[index].after_space = 0;
		c->available_index = index;
	}

	cita_elem_t *el = &c->elem[index];

	// Update available index
	c->available_index = el->prev_index;
	el->prev_index = NAI;

#if 0
	// Traverse the table linearly to find the first free space large enough
	for (int32_t i=0; i < c->elem_count; i++)
		if (c->elem[i].after_space >= size)
		{
			el->prev_index = i;
			el->next_index = c->elem[el->prev_index].next_index;
			break;
		}
#else
	// Traverse the table in linked order to find the first free space large enough
	int32_t i = 0;
	do
	{
		if (c->elem[i].after_space >= size)
		{
			el->prev_index = i;
			el->next_index = c->elem[el->prev_index].next_index;
			break;
		}

		i = c->elem[i].next_index;
	}
	while (i);
#endif

	// Get memory from the end if no suitable space was found
	if (el->prev_index == NAI)
	{
		// New element is added after the last one
		el->prev_index = c->elem[0].prev_index;
		el->next_index = 0;
	}

	// Write the element
	el->addr = c->elem[el->prev_index].addr_after;		// address of buffer
	el->addr_after = cita_align_up(el->addr + size);	// address after this buffer
	el->after_space = c->elem[el->next_index].addr - el->addr_after;			// space after this buffer
	c->elem[el->prev_index].after_space = el->addr - c->elem[el->prev_index].addr_after;	// space before this buffer
	#ifndef CITA_EXCL_TIME
	el->extra.time_created = el->extra.time_modified = c->timestamp;
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
	c->elem[el->prev_index].next_index = index;
	c->elem[el->next_index].prev_index = index;

	// If the buffer is added at the end of the memory
	if (el->next_index == 0)
	{
		el->after_space = 0;

		// Enlarge memory if needed
		cita_enlarge_memory(el->addr_after);

		// Report failure to obtain enough 
		if (el->addr_after > CITA_MEM_END)
		{
			CITA_REPORT("cita_malloc(%zd): new buffer would start at %#zx and end at %#zx (%.1f MB) but the memory can only be enlarged to %#zx (%.1f MB)", size, el->addr, el->addr_after, el->addr_after/1048576., CITA_MEM_END, CITA_MEM_END/1048576.);
			cita_free((void *) el->addr);
			return NULL;
		}
	}

	#ifdef CITA_MAP_SCALE
	cita_map_update_range(el->addr, el->addr_after);
	#endif

	cita_check_links_internal(__func__, __LINE__);

	return (void *) el->addr;
}

void *cita_calloc(size_t nmemb, size_t size)
{
	void *ptr = cita_malloc(nmemb*size);
	memset(ptr, 0, nmemb*size);
	return ptr;
}

void *cita_realloc(void *ptr, size_t size)
{
	size_t addr = (size_t) ptr;

	cita_table_init();
	cita_event_counter++;
	cita_check_links_internal(__func__, __LINE__);

	if (ptr == NULL)
		return cita_malloc(size);

	// Find the table index of the buffer to free
	int32_t index = cita_table_find_buffer(addr, 1);
	if (index == NAI)
	{
		CITA_REPORT("cita_realloc(%#zx, %zd): buffer not found. Input info says \"%s\"", addr, size, cita_input_info);
		return NULL;
	}

	cita_elem_t *el = &c->elem[index];

	// Check space from the start of this buffer to next buffer to see if there's already enough room
	size_t space = c->elem[el->next_index].addr - el->addr;
	if (el->next_index == 0)	// if this buffer is at the end
	{
		// Enlarge memory if needed
		if (el->addr + size > CITA_MEM_END)
			cita_enlarge_memory(el->addr + size);

		space = CITA_MEM_END - el->addr;
	}

	if (space >= size)
	{
		// If so update the end of the buffer as well as the size of the space after it
		el->addr_after = cita_align_up(el->addr + size);
		el->after_space = c->elem[el->next_index].addr - el->addr_after;

		#ifdef CITA_MAP_SCALE
		cita_map_update_range(el->addr, el->addr_after);
		#endif
	}
	else
	{
		// Copy the element, free the buffer, re-allocate it with the same table index, copy the buffer and extras
		cita_elem_t el_copy = *el;
		#ifdef CITA_MAP_SCALE
		if (index == 2)
			cita_map_update_skip = 1;
		#endif
		cita_free_core(ptr, 0);		// the second argument preserves the data
		ptr = cita_malloc(size);
		#ifdef CITA_MAP_SCALE
		if (index == 2)
			cita_map_update_skip = 0;
		#endif
		if (index == 1)			// repoint c->elem if it's what we just moved
			c->elem = ptr;
		el = &c->elem[index];		// needed if it's c->elem we're reallocating
		memmove(ptr, (void *) el_copy.addr, el_copy.addr_after - el_copy.addr);

		#ifdef CITA_FREE_PATTERN
		// Avoid overlap
		size_t erasable_top = el->addr + el_copy.addr_after - el_copy.addr;
		if (el->addr <= el_copy.addr && el_copy.addr < erasable_top)
			el_copy.addr = el->addr_after;
		if (el->addr <= el_copy.addr_after && el_copy.addr_after < erasable_top)
			el_copy.addr_after = el->addr;

		// Clean the old data
		if (el_copy.addr_after > el_copy.addr)
			memset((void *) el_copy.addr, CITA_FREE_PATTERN, el_copy.addr_after - el_copy.addr);
		#endif

		// Copy extra info and set timestamp
		memcpy(&el->extra, &el_copy.extra, sizeof(cita_extra_t));
		#ifndef CITA_EXCL_TIME
		el->extra.time_modified = c->timestamp;
		#endif
	}

	cita_check_links_internal(__func__, __LINE__);
	return (void *) el->addr;
}

#undef c
#endif // CITA_IMPLEMENTATION
