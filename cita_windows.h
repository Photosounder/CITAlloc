// Header part
#ifndef H_CITA_WIN
#define H_CITA_WIN

  #ifndef CITA_TLS
    #define CITA_TLS _Thread_local
  #endif

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
	size_t mem_max;
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
  #undef alloc_enough
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
    #define CITA_INDEX_TYPE uint32_t	// means there can be 2^32-4 allocations
  #endif
  #define CITA_ALIGN 16			// all allocations will be aligned to 16 bytes
  #define CITA_MAP_SCALE 13		// means a map cell covers 8 kB
  #define CITA_FREE_PATTERN 0xC5	// optional but makes the whole heap very neat
  #define CITA_INFO_LEN 56

  #define CITA_MEM_START ((CITA_ADDR_TYPE) cita_buffer.mem)
  #define CITA_MEM_END cita_buffer.mem_end
  #define CITA_PTR(addr) ((void *) addr)
  #define CITA_ADDR(ptr) ((CITA_ADDR_TYPE) ptr)

  #ifndef CITA_PRINT
    #define CITA_PRINT(fmt, ...) { fprintf(stderr, fmt"\n", ##__VA_ARGS__); }
  #endif
  #ifndef CITA_REPORT
  #ifdef CITA_REPORT_TO_STDERR
    #define CITA_REPORT(fmt, ...) { CITA_PRINT(fmt, ##__VA_ARGS__) }
  #else
    char cita_report_str[256];
    #include <winuser.h>
    #define CITA_REPORT(fmt, ...) { snprintf(cita_report_str, sizeof(cita_report_str), fmt, ##__VA_ARGS__); MessageBoxA(NULL, cita_report_str, "CIT Alloc report", MB_OK | MB_ICONERROR); }
  #endif
  #endif

#include <synchapi.h>
CRITICAL_SECTION cita_mutex;
#define CITA_LOCK { cita_win_init(); EnterCriticalSection(&cita_mutex); }
#define CITA_UNLOCK LeaveCriticalSection(&cita_mutex);

#ifndef _MEMORYAPI_H_
  extern __declspec(dllimport) void *VirtualAlloc(void *lpAddress, size_t dwSize, unsigned long flAllocationType, unsigned long flProtect);
  extern __declspec(dllimport) size_t VirtualQuery(const void *lpAddress, MEMORY_BASIC_INFORMATION *lpBuffer, size_t dwLength);
#endif
#ifndef _ERRHANDLING_H_
  extern unsigned long GetLastError();
#endif

size_t windows_memory_max_usable_block(uintptr_t *base_addr)
{
	MEMORY_BASIC_INFORMATION mbi;

	char *address = 0;
	size_t max_usable_block = 0;

	// Go through the ranges of the memory map
	while (VirtualQuery(address, &mbi, sizeof(mbi)))
	{
		if (mbi.State == MEM_FREE)
		{
			uintptr_t start_addr = (uintptr_t) mbi.BaseAddress;
			uintptr_t end_addr = start_addr + mbi.RegionSize;

			// Align the start of the range to the next 64 kB boundary
			uintptr_t aligned_start = (start_addr + 65535) & ~((uintptr_t) 65535);

			// If there's still any free space left compare it the the max
			if (aligned_start < end_addr)
			{
				size_t usable_size = end_addr - aligned_start;
				if (usable_size > max_usable_block)
				{
					max_usable_block = usable_size;
					if (base_addr)
						*base_addr = aligned_start;
				}
			}
		}

		// Set the start of the next range
		address = (char *) mbi.BaseAddress + mbi.RegionSize;
	}

	return max_usable_block;
}

static void cita_win_init()
{
	// Init
	if (cita_buffer.mem == NULL)
	{
		// Init mutex
		InitializeCriticalSection(&cita_mutex);

		// Reserve virtual memory
		uintptr_t base_addr, round_addr;
		cita_buffer.mem_max = windows_memory_max_usable_block(&base_addr);

		// Round up the base address
		round_addr = base_addr;
		for (int i=1; i < 64; i<<=1)
			round_addr |= round_addr >> i;
		round_addr++;
		cita_buffer.mem_max -= round_addr - base_addr;

		// Limit the size
		if (cita_buffer.mem_max > CITA_WIN_MAX)
			cita_buffer.mem_max = CITA_WIN_MAX;

		// Reserve the memory at the rounded address
		cita_buffer.mem = VirtualAlloc((void *) round_addr, cita_buffer.mem_max, 0x00002000 /*MEM_RESERVE*/, 0x01 /*PAGE_NOACCESS*/);

		if (cita_buffer.mem == NULL)
		{
			CITA_REPORT("cita_mem_enlarge(): failed to reserve memory using VirtualAlloc() for %zd MB. Error: %lu\n", cita_buffer.mem_max>>20, GetLastError());
			exit(EXIT_FAILURE);
		}

		CITA_MEM_END = CITA_MEM_START;
	}
}

static void cita_mem_enlarge(uintptr_t new_end)
{
	// Round up the new end address	(12-bit)
	new_end = (new_end + ((CITA_ADDR_TYPE) 1<<12)-1) & ~(((CITA_ADDR_TYPE) 1<<12)-1);

	// Check size
	if (new_end > CITA_MEM_START + cita_buffer.mem_max)
	{
		CITA_REPORT("cita_mem_enlarge(): cannot allocate %zd MB due to the limit being %zd MB.\n", (new_end-CITA_MEM_START)>>20, cita_buffer.mem_max>>20);
		exit(EXIT_FAILURE);
	}

	// Commit new memory
	if (new_end > CITA_MEM_END)
	{
		void *ret = VirtualAlloc((void *) CITA_MEM_END, new_end-CITA_MEM_START, 0x00001000 /*MEM_COMMIT*/, 0x04 /*PAGE_READWRITE*/);

		if (ret == NULL)
		{
			CITA_REPORT("cita_mem_enlarge(): failed to commit memory using VirtualAlloc() from %zd to %zd MB. Error: %lu\n", (CITA_MEM_END-CITA_MEM_START)>>20, (new_end-CITA_MEM_START)>>20, GetLastError());
			exit(EXIT_FAILURE);
		}

		CITA_MEM_END = new_end;
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
