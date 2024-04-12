#ifdef __wasm__

// Implementation part that suppresses the default allocator
#ifdef CITA_WASM_IMPLEMENTATION_PART1

  // Needed to stop the linker from adding the default implementation
  #include <stddef.h>	// for NULL
  void *malloc(size_t size) { return NULL; }
  void free(void *ptr) {}
  void *calloc(size_t nmemb, size_t size) { return NULL; }
  void *realloc(void *ptr, size_t size)  { return NULL; }

#else // CITA_WASM_IMPLEMENTATION_PART1

// Header part
  #ifndef H_CITA_WASM
  #define H_CITA_WASM
  
    #include "cit_alloc.h"
    #define __wasilibc___functions_malloc_h
    extern void *cita_wasm_malloc(size_t size, const char *filename, const char *func, int line);
    extern void cita_wasm_free(void *ptr, const char *filename, const char *func, int line);
    extern void *cita_wasm_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line);
    extern void *cita_wasm_realloc(void *ptr, size_t size, const char *filename, const char *func, int line);
    #define malloc(s) cita_wasm_malloc((s), __FILE__, __func__, __LINE__)
    #define free(p) cita_wasm_free((p), __FILE__, __func__, __LINE__)
    #define calloc(n,s) cita_wasm_calloc((n), (s), __FILE__, __func__, __LINE__)
    #define realloc(p,s) cita_wasm_realloc((p), (s), __FILE__, __func__, __LINE__)
    
    extern size_t cita_wasm_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line);
    #define alloc_enough(b, nc, acp, se, ir)	(*acp) = cita_wasm_alloc_enough_pattern(b, nc, (*acp), se, ir, 0, __FILE__, __func__, __LINE__)
  
  #endif // H_CITA_WASM
  
// Core implementation
  #ifdef CITA_WASM_IMPLEMENTATION_PART2
  
    #define CITA_ALIGN 16
    #define CITA_FREE_PATTERN 0xC5	// optional but makes the whole heap very neat
    extern unsigned char __heap_base;
    #define CITA_MEM_START ((size_t)&__heap_base)
    #define CITA_MEM_END (__builtin_wasm_memory_size(0) * 65536)
    #define CITA_MEM_ENLARGE(new_end) __builtin_wasm_memory_grow(0, ((new_end)-CITA_MEM_END+65535)>>16)
    char cita_report_cmd[256];
    #define CITA_REPORT(fmt, ...) { sprintf(cita_report_cmd, "Print "fmt, ##__VA_ARGS__); wahe_run_command(cita_report_cmd); wahe_run_command("Debug break"); }
    
    #define CITA_IMPLEMENTATION
    #include "cit_alloc.h"

char input_info[60];

static const char *cita_get_filename(const char *path)
{
	for (int i=strlen(path)-1; i >= 0; i--)
		if (path[i] == '/' || path[i] == '\\')
			return &path[i+1];
	return path;
}

#define ADD_CITA_INFO \
	if (cita_input_info==NULL) { \
		int ret = snprintf(input_info, sizeof(input_info), "%s():%d in %s", func, line, cita_get_filename(filename)); \
		cita_input_info = input_info; \
		}

void *cita_wasm_malloc(size_t size, const char *filename, const char *func, int line)
{
	ADD_CITA_INFO
	void *ptr = cita_malloc(size);
	cita_input_info = NULL;
	return ptr;
}

void cita_wasm_free(void *ptr, const char *filename, const char *func, int line)
{
	cita_free(ptr);
}

void *cita_wasm_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line)
{
	ADD_CITA_INFO
	void *ptr = cita_calloc(nmemb, size);
	cita_input_info = NULL;
	return ptr;
}

void *cita_wasm_realloc(void *ptr, size_t size, const char *filename, const char *func, int line)
{
	ADD_CITA_INFO
	void *new_ptr = cita_realloc(ptr, size);
	cita_input_info = NULL;
	return new_ptr;
}

// This one is added just so that it can report info from the caller
size_t cita_wasm_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line)
{
	size_t newsize;
	void *p;

	if (needed_count > alloc_count)
	{
		newsize = ceil((double) needed_count * inc_ratio);

		// Try realloc to the new larger size
		ADD_CITA_INFO
		p = cita_realloc(*buffer, newsize * size_elem);
		cita_input_info = NULL;

		if (p == NULL)
		{
			CITA_REPORT("cita_realloc(*buffer=%p, size=%zu) failed.\n", (void *) *buffer, newsize * size_elem);
			return alloc_count;
		}
		else
			*buffer = p;

		// Set the new bytes
		memset(&((uint8_t *)(*buffer))[alloc_count * size_elem], pattern, (newsize-alloc_count) * size_elem);

		alloc_count = newsize;
	}

	return alloc_count;
}

  #endif // CITA_WASM_IMPLEMENTATION_PART2

#endif // CITA_WASM_IMPLEMENTATION_PART1

#endif // __wasm__
