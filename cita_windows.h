// Header part
#ifndef H_CITA_WIN
#define H_CITA_WIN

  #ifndef CITA_ADDR_TYPE
    #define CITA_ADDR_TYPE uintptr_t
  #endif

  #include "cit_alloc.h"

  #if UINTPTR_MAX == 0xFFFFFFFFUL
    #define CITA_WIN_MAX UINTPTR_MAX
  #else
    #define CITA_WIN_MAX ((CITA_ADDR_TYPE) 1 << 40)
  #endif

  typedef struct
  {
	uint8_t *mem;
	CITA_ADDR_TYPE mem_end;
  } cita_buffer_t;

  extern cita_buffer_t cita_buffer;

  extern void *cita_win_malloc(size_t size, const char *filename, const char *func, int line);
  extern void cita_win_free(void *buffer_addr, const char *filename, const char *func, int line);
  extern void *cita_win_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line);
  extern void *cita_win_realloc(void *buffer_addr, size_t size, const char *filename, const char *func, int line);
  #define malloc(s) cita_win_malloc((s), __FILE_NAME__, __func__, __LINE__)
  #define free(p) cita_win_free((p), __FILE_NAME__, __func__, __LINE__)
  #define calloc(n,s) cita_win_calloc((n), (s), __FILE_NAME__, __func__, __LINE__)
  #define realloc(p,s) cita_win_realloc((p), (s), __FILE_NAME__, __func__, __LINE__)
  
  extern size_t cita_win_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line);
  #define alloc_enough(b, nc, acp, se, ir)	*(acp) = cita_win_alloc_enough_pattern(b, nc, *(acp), se, ir, 0, __FILE_NAME__, __func__, __LINE__)

  extern size_t cita_win_get_min_size();

  extern const char *cita_get_filename(const char *path);
  extern char input_info[60];
  #define ADD_CITA_INFO \
	if (cita_input_info==NULL) { \
		snprintf(input_info, sizeof(input_info), "%s():%d in %s", func, line, cita_get_filename(filename)); \
		cita_input_info = input_info; \
		}

#endif // H_CITA_WIN

// Core implementation
#ifdef CITA_WIN_IMPLEMENTATION

  cita_buffer_t cita_buffer = {0};

  #ifndef CITA_INDEX_TYPE
    #define CITA_INDEX_TYPE uint16_t	// means there can only be 65535 allocations
  #endif
  #define CITA_ALIGN 16			// all allocations will be aligned to 16 bytes
  #define CITA_MAP_SCALE 13		// means a map cell covers 8 kB
  #define CITA_FREE_PATTERN 0xC5	// optional but makes the whole heap very neat
  #define CITA_INFO_LEN 56

  #define CITA_MEM_START ((CITA_ADDR_TYPE) cita_buffer.mem)
  #define CITA_MEM_END ((CITA_ADDR_TYPE) cita_buffer.mem_end)
  #define CITA_PTR(addr) ((void *) addr)
  #define CITA_ADDR(ptr) ((CITA_ADDR_TYPE) ptr)

  #ifndef CITA_PRINT
    #define CITA_PRINT(fmt, ...) { fprintf(stderr, fmt"\n", ##__VA_ARGS__); }
  #endif
  #ifndef CITA_REPORT
    #define CITA_REPORT(fmt, ...) { CITA_PRINT(fmt, ##__VA_ARGS__) }
  #endif

extern void *VirtualAlloc(void *lpAddress, size_t dwSize, int flAllocationType, int flProtect);
extern int GetLastError();

#include <synchapi.h>
CRITICAL_SECTION cita_mutex;
#define CITA_LOCK { cita_win_init(); EnterCriticalSection(&cita_mutex); }
#define CITA_UNLOCK LeaveCriticalSection(&cita_mutex);

static void cita_win_init()
{
	// Init
	if (cita_buffer.mem == NULL)
	{
		// Init mutex
		InitializeCriticalSection(&cita_mutex);

		// Reserve virtual memory
		cita_buffer.mem = VirtualAlloc(NULL, CITA_WIN_MAX, 0x00002000 /*MEM_RESERVE*/, 0x01 /*PAGE_NOACCESS*/);

		if (cita_buffer.mem == NULL)
		{
			CITA_REPORT("cita_mem_enlarge(): failed to reserve memory using VirtualAlloc() for %zd MB. Error: %d\n", CITA_WIN_MAX>>20, GetLastError());
			exit(EXIT_FAILURE);
		}

		cita_buffer.mem_end = (CITA_ADDR_TYPE) cita_buffer.mem;
	}
}

static void cita_mem_enlarge(size_t new_end)
{
	// Round up the new end address	(12-bit)
	new_end = (new_end + ((CITA_ADDR_TYPE) 1<<12)-1) & ~(((CITA_ADDR_TYPE) 1<<12)-1);

	// Check size
	if (new_end > (CITA_ADDR_TYPE) cita_buffer.mem + CITA_WIN_MAX)
	{
		CITA_REPORT("cita_mem_enlarge(): cannot allocate %zd MB due to the limit being %zd MB.\n", (new_end-(CITA_ADDR_TYPE) cita_buffer.mem)>>20, CITA_WIN_MAX>>20);
		exit(EXIT_FAILURE);
	}

	// Commit new memory
	if (new_end > (CITA_ADDR_TYPE) cita_buffer.mem_end)
	{
		void *ret = VirtualAlloc((void *) cita_buffer.mem_end, new_end - (CITA_ADDR_TYPE) cita_buffer.mem, 0x00001000 /*MEM_COMMIT*/, 0x04 /*PAGE_READWRITE*/);

		if (ret == NULL)
		{
			CITA_REPORT("cita_mem_enlarge(): failed to commit memory using VirtualAlloc() from %zd to %zd MB. Error: %d\n", (cita_buffer.mem_end-(CITA_ADDR_TYPE) cita_buffer.mem)>>20, (new_end-(CITA_ADDR_TYPE) cita_buffer.mem)>>20, GetLastError());
			exit(EXIT_FAILURE);
		}

		cita_buffer.mem_end = new_end;
	}
}

#define CITA_MEM_ENLARGE(new_end) { cita_mem_enlarge((new_end)); }
  
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

void *cita_win_malloc(size_t size, const char *filename, const char *func, int line)
{
	CITA_LOCK
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_malloc(size);
	if (clear_info) cita_input_info = NULL;
	CITA_UNLOCK
	return ptr;
}

void cita_win_free(void *ptr, const char *filename, const char *func, int line)
{
	CITA_LOCK
	cita_free(ptr);
	CITA_UNLOCK
}

void *cita_win_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line)
{
	CITA_LOCK
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_calloc(nmemb, size);
	if (clear_info) cita_input_info = NULL;
	CITA_UNLOCK
	return ptr;
}

void *cita_win_realloc(void *ptr, size_t size, const char *filename, const char *func, int line)
{
	CITA_LOCK
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *new_ptr = cita_realloc(ptr, size);
	if (clear_info) cita_input_info = NULL;
	CITA_UNLOCK
	return new_ptr;
}

// This one is added just so that it can report info from the caller
size_t cita_win_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line)
{
	size_t newsize;
	void *p;
	CITA_LOCK

	if (needed_count > alloc_count)
	{
		extern double ceil(double x);
		newsize = ceil((double) needed_count * inc_ratio);

		// Try realloc to the new larger size
		int clear_info = (cita_input_info == NULL);
		ADD_CITA_INFO
		p = cita_realloc(*buffer, newsize * size_elem);
		if (clear_info) cita_input_info = NULL;

		if (p == NULL)
		{
			CITA_REPORT("cita_realloc(*buffer=%p, size=%zu) failed.\n", (void *) *buffer, newsize * size_elem);
			CITA_UNLOCK
			return alloc_count;
		}
		else
			*buffer = p;

		// Set the new bytes
		memset(&((uint8_t *)(*buffer))[alloc_count * size_elem], pattern, (newsize-alloc_count) * size_elem);

		alloc_count = newsize;
	}

	CITA_UNLOCK
	return alloc_count;
}

#endif // CITA_WIN_IMPLEMENTATION
