// Header part
#ifndef H_CITA_ARENA
#define H_CITA_ARENA

  #ifndef CITA_TLS
    #define CITA_TLS _Thread_local
  #endif

  #ifndef CITA_ADDR_TYPE
    #define CITA_ADDR_TYPE uint32_t
  #endif

  #include "cit_alloc.h"

  typedef struct
  {
	uint8_t *mem;
	size_t mem_as;
  } cita_arena_t;

  extern CITA_TLS cita_arena_t *cita_arena_global;

  extern CITA_ADDR_TYPE cita_arena_malloc(cita_arena_t *arena, size_t size, const char *filename, const char *func, int line);
  extern void cita_arena_free(cita_arena_t *arena, CITA_ADDR_TYPE buffer_addr, const char *filename, const char *func, int line);
  extern CITA_ADDR_TYPE cita_arena_calloc(cita_arena_t *arena, size_t nmemb, size_t size, const char *filename, const char *func, int line);
  extern CITA_ADDR_TYPE cita_arena_realloc(cita_arena_t *arena, CITA_ADDR_TYPE buffer_addr, size_t size, const char *filename, const char *func, int line);
  #define arena_malloc(a,s) cita_arena_malloc((a), (s), __FILE_NAME__, __func__, __LINE__)
  #define arena_free(a,p) cita_arena_free((a), (p), __FILE_NAME__, __func__, __LINE__)
  #define arena_calloc(a,n,s) cita_arena_calloc((a), (n), (s), __FILE_NAME__, __func__, __LINE__)
  #define arena_realloc(a,p,s) cita_arena_realloc((a), (p), (s), __FILE_NAME__, __func__, __LINE__)
  
  extern size_t cita_arena_alloc_enough_pattern(cita_arena_t *arena, CITA_ADDR_TYPE *buffer_addr, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line);
  #define arena_alloc_enough(a, b, nc, acp, se, ir)	*(acp) = cita_arena_alloc_enough_pattern(a, b, nc, *(acp), se, ir, 0, __FILE_NAME__, __func__, __LINE__)

  extern size_t cita_arena_get_min_size(cita_arena_t *arena);

  extern const char *cita_get_filename(const char *path);
  extern char input_info[60];
  #define ADD_CITA_INFO \
	if (cita_input_info==NULL) { \
		snprintf(input_info, sizeof(input_info), "%s():%d in %s", func, line, cita_get_filename(filename)); \
		cita_input_info = input_info; \
		}

#endif // H_CITA_ARENA

// Core implementation
#ifdef CITA_ARENA_IMPLEMENTATION

  CITA_TLS cita_arena_t *cita_arena_global = NULL;

  #ifndef CITA_INDEX_TYPE
    #define CITA_INDEX_TYPE uint16_t	// means there can only be 65535 allocations
  #endif
  #define CITA_ALIGN 16			// all allocations will be aligned to 16 bytes
  #define CITA_MAP_SCALE 13		// means a map cell covers 8 kB
  #define CITA_FREE_PATTERN 0xC5	// optional but makes the whole heap very neat
  #define CITA_INFO_LEN 56

  #define CITA_MEM_START ((CITA_ADDR_TYPE) 0)
  #define CITA_MEM_END (cita_arena_global->mem_as)
  #define CITA_MEM_ENLARGE(new_end) { cita_arena_global->mem_as = ((new_end) + ((CITA_ADDR_TYPE) 1<<16)-1) & ~(((CITA_ADDR_TYPE) 1<<16)-1); cita_arena_global->mem = realloc(cita_arena_global->mem, cita_arena_global->mem_as); }
  #define CITA_PTR(addr) ((void *) &cita_arena_global->mem[addr])
  #define CITA_ADDR(ptr) ((ptr) ? (CITA_ADDR_TYPE) ((size_t) (ptr) - (size_t) cita_arena_global->mem) : 0)

  #ifndef CITA_PRINT
    #define CITA_PRINT(fmt, ...) { fprintf(stderr, fmt"\n", ##__VA_ARGS__); }
  #endif
  #ifndef CITA_REPORT
    #define CITA_REPORT(fmt, ...) { CITA_PRINT(fmt, ##__VA_ARGS__) }
  #endif
  
  #define CITA_IMPLEMENTATION
  #include "cit_alloc.h"

char input_info[60];

const char *cita_get_filename(const char *path)
{
	for (int i=strlen(path)-1; i >= 0; i--)
		if (path[i] == '/' || path[i] == '\\')
			return &path[i+1];
	return path;
}

CITA_ADDR_TYPE cita_arena_malloc(cita_arena_t *arena, size_t size, const char *filename, const char *func, int line)
{
	cita_arena_global = arena;
	cita_table = (cita_table_t *) cita_arena_global->mem;
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_malloc(size);
	if (clear_info) cita_input_info = NULL;
	return CITA_ADDR(ptr);
}

void cita_arena_free(cita_arena_t *arena, CITA_ADDR_TYPE buffer_addr, const char *filename, const char *func, int line)
{
	cita_arena_global = arena;
	cita_table = (cita_table_t *) cita_arena_global->mem;
	cita_free(CITA_PTR(buffer_addr));
}

CITA_ADDR_TYPE cita_arena_calloc(cita_arena_t *arena, size_t nmemb, size_t size, const char *filename, const char *func, int line)
{
	cita_arena_global = arena;
	cita_table = (cita_table_t *) cita_arena_global->mem;
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_calloc(nmemb, size);
	if (clear_info) cita_input_info = NULL;
	return CITA_ADDR(ptr);
}

CITA_ADDR_TYPE cita_arena_realloc(cita_arena_t *arena, CITA_ADDR_TYPE buffer_addr, size_t size, const char *filename, const char *func, int line)
{
	cita_arena_global = arena;
	cita_table = (cita_table_t *) cita_arena_global->mem;
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *new_ptr = cita_realloc(CITA_PTR(buffer_addr), size);
	if (clear_info) cita_input_info = NULL;
	return CITA_ADDR(new_ptr);
}

// This one is added just so that it can report info from the caller
size_t cita_arena_alloc_enough_pattern(cita_arena_t *arena, CITA_ADDR_TYPE *buffer_addr, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line)
{
	cita_arena_global = arena;
	cita_table = (cita_table_t *) cita_arena_global->mem;
	size_t newsize;
	void *p;

	if (needed_count > alloc_count)
	{
		newsize = (double) needed_count * inc_ratio + 0.9999999999999999;

		// Try realloc to the new larger size
		int clear_info = (cita_input_info == NULL);
		ADD_CITA_INFO
		p = cita_realloc(CITA_PTR(*buffer_addr), newsize * size_elem);
		if (clear_info) cita_input_info = NULL;

		if (p == NULL)
		{
			CITA_REPORT("cita_realloc(*buffer_addr=%#zx, size=%zu) failed.\n", (size_t) *buffer_addr, newsize * size_elem);
			return alloc_count;
		}
		else
			*buffer_addr = CITA_ADDR(p);

		// Set the new bytes
		memset(&((uint8_t *)p)[alloc_count * size_elem], pattern, (newsize-alloc_count) * size_elem);

		alloc_count = newsize;
	}

	return alloc_count;
}

size_t cita_arena_get_min_size(cita_arena_t *arena)
{
	cita_table = (cita_table_t *) arena->mem;
	return cita_find_end_addr();
}

#endif // CITA_ARENA_IMPLEMENTATION
