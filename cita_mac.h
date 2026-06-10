// Header part
#ifndef H_CITA_MAC
#define H_CITA_MAC

  #include <stddef.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>

  #ifdef CITA_MAC_IMPLEMENTATION
    #include <errno.h>
    #include <pthread.h>
    #include <sys/mman.h>
    #include <unistd.h>
    #if !defined(CITA_REPORT) && !defined(CITA_REPORT_TO_STDERR)
      #include <CoreFoundation/CoreFoundation.h>
      #include <signal.h>
      #include <stdarg.h>
      #ifndef SIGTRAP
        #define SIGTRAP 5
      #endif
    #endif
  #endif

  #ifndef CITA_TLS
    #define CITA_TLS _Thread_local
  #endif

  #ifndef CITA_ADDR_TYPE
    #define CITA_ADDR_TYPE uintptr_t
  #endif

  #ifndef __FILE_NAME__
    #define __FILE_NAME__ __FILE__
  #endif

  #include "cit_alloc.h"

  #ifndef CITA_MAC_MAX
    #if UINTPTR_MAX == 0xFFFFFFFFUL
      #define CITA_MAC_MAX UINTPTR_MAX
    #else
      #define CITA_MAC_MAX ((CITA_ADDR_TYPE) 1 << 40)
    #endif
  #endif

  #define CITA_TIME_IS_COUNTER

  typedef struct
  {
	uint8_t *mem;
	CITA_ADDR_TYPE mem_end;
	size_t mem_max;
  } cita_buffer_t;

  extern cita_buffer_t cita_buffer;

  extern void *cita_mac_malloc(size_t size, const char *filename, const char *func, int line);
  extern void cita_mac_free(void *buffer_addr, const char *filename, const char *func, int line);
  extern void *cita_mac_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line);
  extern void *cita_mac_realloc(void *buffer_addr, size_t size, const char *filename, const char *func, int line);
  #define malloc(s) cita_mac_malloc((s), __FILE_NAME__, __func__, __LINE__)
  #define free(p) cita_mac_free((p), __FILE_NAME__, __func__, __LINE__)
  #define calloc(n,s) cita_mac_calloc((n), (s), __FILE_NAME__, __func__, __LINE__)
  #define realloc(p,s) cita_mac_realloc((p), (s), __FILE_NAME__, __func__, __LINE__)

  extern size_t cita_mac_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line);
  #undef alloc_enough
  #define alloc_enough(b, nc, acp, se, ir)	*(acp) = cita_mac_alloc_enough_pattern(b, nc, *(acp), se, ir, 0, __FILE_NAME__, __func__, __LINE__)

  extern const char *cita_get_filename(const char *path);
  extern char input_info[60];
  #define ADD_CITA_INFO \
	if (cita_input_info==NULL) { \
		snprintf(input_info, sizeof(input_info), "%s():%d in %s", func, line, cita_get_filename(filename)); \
		cita_input_info = input_info; \
		}

#endif // H_CITA_MAC

// Core implementation
#ifdef CITA_MAC_IMPLEMENTATION

  #if !defined(__APPLE__) || !defined(__MACH__)
    #error cita_mac.h requires macOS
  #endif

  cita_buffer_t cita_buffer = {0};

  #ifndef CITA_INDEX_TYPE
    #define CITA_INDEX_TYPE uint32_t	// means there can be 2^32-4 allocations
  #endif
  #define CITA_ALIGN 16			// all allocations will be aligned to 16 bytes
  #define CITA_MAP_SCALE 16		// means a map cell covers 64 kB
  #define CITA_FREE_PATTERN 0xC5	// optional but makes the whole heap very neat
  #define CITA_INFO_LEN 48
  #define CITA_GAP_LINKS

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
      char cita_report_str[300];
      static int cita_mac_report(const char *fmt, ...);
      #define CITA_MAC_USE_CF_REPORT
      #define CITA_REPORT(fmt, ...) { if (cita_mac_report(fmt, ##__VA_ARGS__)) raise(SIGTRAP); }
    #endif
  #endif

  static pthread_mutex_t cita_mutex = PTHREAD_MUTEX_INITIALIZER;
  static pthread_once_t cita_init_once = PTHREAD_ONCE_INIT;
  static size_t cita_mac_page_size = 4096;
  static int cita_mac_page_shift = 12;

  static void cita_mac_init(void);
  #define CITA_LOCK { pthread_once(&cita_init_once, cita_mac_init); pthread_mutex_lock(&cita_mutex); }
  #define CITA_UNLOCK pthread_mutex_unlock(&cita_mutex);

#ifdef CITA_MAC_USE_CF_REPORT
static int cita_mac_report(const char *fmt, ...)
{
	// Format the allocator report and keep room for the debugger prompt.
	va_list args;
	va_start(args, fmt);
	vsnprintf(cita_report_str, sizeof(cita_report_str), fmt, args);
	va_end(args);
	cita_report_str[sizeof(cita_report_str) - 1] = '\0';

	// Append the same debugging question used by the Windows message box.
	size_t len = strlen(cita_report_str);
	if (len < sizeof(cita_report_str) - 1)
		snprintf(&cita_report_str[len], sizeof(cita_report_str) - len, "\n\nDebug?");

	// Convert the report body into a Core Foundation string for the alert.
	CFStringRef message = CFStringCreateWithCString(NULL, cita_report_str, kCFStringEncodingUTF8);
	if (message == NULL)
	{
		// Fall back to stderr when Core Foundation cannot create the message.
		CITA_PRINT("%s", cita_report_str);
		return 0;
	}

	// Show a simple Debug or Ignore alert and record the selected button.
	CFOptionFlags response = kCFUserNotificationAlternateResponse;
	SInt32 err = CFUserNotificationDisplayAlert(0, kCFUserNotificationStopAlertLevel, NULL, NULL, NULL, CFSTR("CIT Alloc report"), message, CFSTR("Debug"), CFSTR("Ignore"), NULL, &response);
	CFRelease(message);

	// Break only when the user chooses the default Debug button.
	return err == 0 && response == kCFUserNotificationDefaultResponse;
}
#endif

static CITA_ADDR_TYPE cita_mac_page_align(CITA_ADDR_TYPE addr)
{
	// Round the address up to the next VM page boundary.
	CITA_ADDR_TYPE page_mask = (CITA_ADDR_TYPE) cita_mac_page_size - 1;
	return (addr + page_mask) & ~page_mask;
}

static void cita_mac_init(void)
{
	// Record the host page size used for VM commit and decommit operations.
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		cita_mac_page_size = (size_t) page_size;

	// Store the page size as a shift for the core shrink helper.
	cita_mac_page_shift = 0;
	for (size_t page = cita_mac_page_size; page > 1; page >>= 1)
		cita_mac_page_shift++;

	// Reserve a large no-access virtual address range for the allocator heap.
	size_t reserve_size = (size_t) CITA_MAC_MAX;
	size_t min_reserve_size = reserve_size < ((size_t) 64 << 20) ? reserve_size : ((size_t) 64 << 20);
	while (reserve_size >= min_reserve_size && reserve_size > 0)
	{
		void *mem = mmap(NULL, reserve_size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
		if (mem != MAP_FAILED)
		{
			cita_buffer.mem = mem;
			cita_buffer.mem_max = reserve_size;
			break;
		}
		reserve_size >>= 1;
	}

	// Stop early if macOS could not reserve a usable heap range.
	if (cita_buffer.mem == NULL)
	{
		CITA_REPORT("cita_mac_init(): failed to reserve memory using mmap(). Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	// Start with no committed bytes inside the reserved range.
	CITA_MEM_END = CITA_MEM_START;
}

static void cita_mem_enlarge(CITA_ADDR_TYPE new_end)
{
	// Round the requested end address up to a VM page boundary.
	new_end = cita_mac_page_align(new_end);

	// Reject requests that would pass the reserved heap range.
	if (new_end > CITA_MEM_START + cita_buffer.mem_max)
	{
		CITA_REPORT("cita_mem_enlarge(): cannot allocate %zd MB due to the limit being %zd MB.\n", (new_end-CITA_MEM_START)>>20, cita_buffer.mem_max>>20);
		exit(EXIT_FAILURE);
	}

	// Commit newly needed pages by allowing reads and writes.
	if (new_end > CITA_MEM_END)
	{
		CITA_ADDR_TYPE old_end = CITA_MEM_END;
		if (mprotect((void *) old_end, (size_t) (new_end - old_end), PROT_READ | PROT_WRITE) != 0)
		{
			CITA_REPORT("cita_mem_enlarge(): failed to commit memory using mprotect() from %zd to %zd MB. Error: %s\n", (old_end-CITA_MEM_START)>>20, (new_end-CITA_MEM_START)>>20, strerror(errno));
			exit(EXIT_FAILURE);
		}

		CITA_MEM_END = new_end;
	}
}

#define CITA_MEM_ENLARGE(new_end) { cita_mem_enlarge((new_end)); }
static void cita_mac_mem_shrink(void);
#define CITA_MEM_SHRINK() { cita_mac_mem_shrink(); }

#define CITA_IMPLEMENTATION
#include "cit_alloc.h"

static int cita_mac_decommit(void *addr, size_t size)
{
	// Replace committed pages with a fresh no-access mapping.
	void *ret = mmap(addr, size, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
	return ret == addr;
}

static void cita_mac_mem_shrink(void)
{
	// Check whether enough committed memory can be recovered.
	CITA_ADDR_TYPE new_end = cita_shrink_new_end((CITA_ADDR_TYPE) 32 << 20, cita_mac_page_shift);
	if (new_end == CITA_MEM_END)
		return;

	// Decommit the recovered tail while preserving the reserved address range.
	CITA_ADDR_TYPE old_end = CITA_MEM_END;
	if (cita_mac_decommit((void *) new_end, (size_t) (old_end - new_end)))
	{
		CITA_MEM_END = new_end;
		cita_map_ensure_capacity();
	}
	else
	{
		CITA_REPORT("cita_mac_mem_shrink(): failed to decommit memory from %zd to %zd MB. Error: %s\n", (new_end-CITA_MEM_START)>>20, (old_end-CITA_MEM_START)>>20, strerror(errno));
	}
}

char input_info[60];

const char *cita_get_filename(const char *path)
{
	// Walk backward to find the last path separator.
	for (int i=strlen(path)-1; i >= 0; i--)
		if (path[i] == '/')
			return &path[i+1];

	// Use the whole path when no separator was found.
	return path;
}

void *cita_mac_malloc(size_t size, const char *filename, const char *func, int line)
{
	CITA_LOCK
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_malloc(size);
	if (clear_info) cita_input_info = NULL;
	CITA_UNLOCK
	return ptr;
}

void cita_mac_free(void *ptr, const char *filename, const char *func, int line)
{
	CITA_LOCK
	ADD_CITA_INFO
	cita_free(ptr);
	CITA_UNLOCK
}

void *cita_mac_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line)
{
	CITA_LOCK
	int clear_info = (cita_input_info == NULL);
	ADD_CITA_INFO
	void *ptr = cita_calloc(nmemb, size);
	if (clear_info) cita_input_info = NULL;
	CITA_UNLOCK
	return ptr;
}

void *cita_mac_realloc(void *ptr, size_t size, const char *filename, const char *func, int line)
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
size_t cita_mac_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line)
{
	// Grow the buffer only when the requested count exceeds its allocation.
	if (needed_count > alloc_count)
	{
		// Compute the new allocation count using the caller's growth ratio.
		size_t newsize = (double) needed_count * inc_ratio + 0.9999999999999999;

		// Try realloc to the new larger size while recording caller information.
		CITA_LOCK
		int clear_info = (cita_input_info == NULL);
		ADD_CITA_INFO
		void *p = cita_realloc(*buffer, newsize * size_elem);
		if (clear_info) cita_input_info = NULL;

		if (p == NULL)
		{
			// Report failure without changing the old allocation count.
			CITA_REPORT("cita_realloc(*buffer=%p, size=%zu) failed.\n", (void *) *buffer, newsize * size_elem);
			CITA_UNLOCK
			return alloc_count;
		}
		else
		{
			// Store the resized buffer pointer for the caller.
			*buffer = p;
		}
		CITA_UNLOCK

		// Set the newly allocated bytes to the requested pattern.
		memset(&((uint8_t *)(*buffer))[alloc_count * size_elem], pattern, (newsize-alloc_count) * size_elem);

		// Return the new allocation count to the caller.
		alloc_count = newsize;
	}

	// Return the current allocation count unchanged when no growth was needed.
	return alloc_count;
}

#endif // CITA_MAC_IMPLEMENTATION
