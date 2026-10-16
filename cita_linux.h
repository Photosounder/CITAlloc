// Header part
#ifndef H_CITA_LINUX
#define H_CITA_LINUX

  #include <stddef.h>
  #include <stdint.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>

  #ifdef CITA_LINUX_IMPLEMENTATION
    #include <errno.h>
    #include <pthread.h>
    #include <sys/mman.h>
    #include <unistd.h>
  #endif

  #ifndef CITA_TLS
    #define CITA_TLS _Thread_local
  #endif

  #ifndef CITA_ADDR_TYPE
    #define CITA_ADDR_TYPE uintptr_t
  #endif

  #ifndef CITA_INDEX_TYPE
    #define CITA_INDEX_TYPE uint32_t
  #endif

  #ifndef __FILE_NAME__
    #define __FILE_NAME__ __FILE__
  #endif

  #include "cit_alloc.h"

  #ifndef CITA_LINUX_MAX
    #if UINTPTR_MAX == 0xFFFFFFFFUL
      #define CITA_LINUX_MAX UINTPTR_MAX
    #else
      #define CITA_LINUX_MAX ((CITA_ADDR_TYPE) 1 << 40)
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

  extern void *cita_linux_malloc(size_t size, const char *filename, const char *func, int line);
  extern void cita_linux_free(void *buffer_addr, const char *filename, const char *func, int line);
  extern void *cita_linux_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line);
  extern void *cita_linux_realloc(void *buffer_addr, size_t size, const char *filename, const char *func, int line);
  #define malloc(s) cita_linux_malloc((s), __FILE_NAME__, __func__, __LINE__)
  #define free(p) cita_linux_free((p), __FILE_NAME__, __func__, __LINE__)
  #define calloc(n,s) cita_linux_calloc((n), (s), __FILE_NAME__, __func__, __LINE__)
  #define realloc(p,s) cita_linux_realloc((p), (s), __FILE_NAME__, __func__, __LINE__)

  extern size_t cita_linux_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count, size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line);
  #undef alloc_enough
  #define alloc_enough(b, nc, acp, se, ir) *(acp) = cita_linux_alloc_enough_pattern(b, nc, *(acp), se, ir, 0, __FILE_NAME__, __func__, __LINE__)

  extern const char *cita_get_filename(const char *path);
  extern char input_info[60];
  #define ADD_CITA_INFO \
    int clear_info = (cita_input_info == NULL); \
    if (cita_input_info == NULL) { \
      snprintf(input_info, sizeof(input_info), "%s():%d in %s", func, line, cita_get_filename(filename)); \
      cita_input_info = input_info; \
    }
  #define RESET_CITA_INFO \
    if (clear_info) cita_input_info = NULL;

#endif // H_CITA_LINUX

// Core implementation
#ifdef CITA_LINUX_IMPLEMENTATION

  #ifndef __linux__
    #error cita_linux.h requires Linux
  #endif

  #ifndef MAP_ANONYMOUS
    #error Enable MAP_ANONYMOUS with -D_DEFAULT_SOURCE or -D_GNU_SOURCE
  #endif

  cita_buffer_t cita_buffer = {0};

  #define CITA_ALIGN 16
  #define CITA_MAP_SCALE 16
  #define CITA_FREE_PATTERN 0xC5
  #define CITA_INFO_LEN 48
  #define CITA_GAP_LINKS

  #define CITA_MEM_START ((CITA_ADDR_TYPE) cita_buffer.mem)
  #define CITA_MEM_END cita_buffer.mem_end
  #define CITA_PTR(addr) ((void *) (addr))
  #define CITA_ADDR(ptr) ((CITA_ADDR_TYPE) (ptr))

  #ifndef CITA_PRINT
    #define CITA_PRINT(fmt, ...) { fprintf(stderr, fmt "\n", ##__VA_ARGS__); }
  #endif
  #ifndef CITA_REPORT
    #define CITA_REPORT(fmt, ...) { CITA_PRINT(fmt, ##__VA_ARGS__) }
  #endif

  static pthread_mutex_t cita_mutex = PTHREAD_MUTEX_INITIALIZER;
  static pthread_once_t cita_init_once = PTHREAD_ONCE_INIT;
  static size_t cita_linux_page_size = 4096;
  static int cita_linux_page_shift = 12;

  static void cita_linux_init(void);
  #define CITA_LOCK { pthread_once(&cita_init_once, cita_linux_init); pthread_mutex_lock(&cita_mutex); }
  #define CITA_UNLOCK pthread_mutex_unlock(&cita_mutex);

static CITA_ADDR_TYPE cita_linux_page_align(CITA_ADDR_TYPE addr)
{
  // Round the heap end to the next page boundary
  CITA_ADDR_TYPE mask = (CITA_ADDR_TYPE) cita_linux_page_size - 1;
  return (addr + mask) & ~mask;
}

static void cita_linux_init(void)
{
  // Read the page size before reserving the heap
  long page_size = sysconf(_SC_PAGESIZE);
  if (page_size > 0)
    cita_linux_page_size = (size_t) page_size;
  cita_linux_page_shift = 0;
  for (size_t page = cita_linux_page_size; page > 1; page >>= 1)
    cita_linux_page_shift++;

  // Reserve an inaccessible address range with smaller fallbacks
  size_t reserve_size = (size_t) CITA_LINUX_MAX;
  size_t min_reserve_size = reserve_size < ((size_t) 64 << 20) ? reserve_size : ((size_t) 64 << 20);
  while (reserve_size >= min_reserve_size && reserve_size > 0)
  {
    void *mem = mmap(NULL, reserve_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem != MAP_FAILED)
    {
      cita_buffer.mem = mem;
      cita_buffer.mem_max = reserve_size;
      break;
    }
    reserve_size >>= 1;
  }

  // Report failure before the shared allocator accesses the heap
  if (!cita_buffer.mem)
  {
    CITA_REPORT("cita_linux_init(): mmap reservation failed: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }
  CITA_MEM_END = CITA_MEM_START;
}

static void cita_mem_enlarge(CITA_ADDR_TYPE new_end)
{
  // Commit complete pages while keeping the reserved address range fixed
  new_end = cita_linux_page_align(new_end);
  if (new_end > CITA_MEM_START + cita_buffer.mem_max)
  {
    CITA_REPORT("cita_mem_enlarge(): cannot allocate %zu MB beyond the %zu MB reservation",
      (size_t) (new_end - CITA_MEM_START) >> 20, cita_buffer.mem_max >> 20);
    exit(EXIT_FAILURE);
  }
  if (new_end > CITA_MEM_END)
  {
    CITA_ADDR_TYPE old_end = CITA_MEM_END;
    if (mprotect((void *) old_end, (size_t) (new_end - old_end), PROT_READ | PROT_WRITE) != 0)
    {
      CITA_REPORT("cita_mem_enlarge(): mprotect failed: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    CITA_MEM_END = new_end;
  }
}

#define CITA_MEM_ENLARGE(new_end) { cita_mem_enlarge((new_end)); }
static void cita_linux_mem_shrink(void);
#define CITA_MEM_SHRINK() { cita_linux_mem_shrink(); }

#define CITA_IMPLEMENTATION
#include "cit_alloc.h"

static void cita_linux_mem_shrink(void)
{
  // Find a page aligned unused tail large enough to release
  CITA_ADDR_TYPE new_end = cita_shrink_new_end((CITA_ADDR_TYPE) 32 << 20, cita_linux_page_shift);
  if (new_end == CITA_MEM_END)
    return;

  // Revoke access and discard the old pages while retaining the reservation
  CITA_ADDR_TYPE old_end = CITA_MEM_END;
  size_t size = (size_t) (old_end - new_end);
  if (mprotect((void *) new_end, size, PROT_NONE) != 0)
  {
    CITA_REPORT("cita_linux_mem_shrink(): mprotect failed: %s", strerror(errno));
    return;
  }
  if (madvise((void *) new_end, size, MADV_DONTNEED) != 0)
  {
    int error = errno;
    if (mprotect((void *) new_end, size, PROT_READ | PROT_WRITE) != 0)
    {
      CITA_REPORT("cita_linux_mem_shrink(): could not restore pages: %s", strerror(errno));
      exit(EXIT_FAILURE);
    }
    CITA_REPORT("cita_linux_mem_shrink(): madvise failed: %s", strerror(error));
    return;
  }
  CITA_MEM_END = new_end;
  cita_map_ensure_capacity();
}

char input_info[60];

const char *cita_get_filename(const char *path)
{
  // Return the basename used by allocation origin labels
  const char *filename = strrchr(path, '/');
  return filename ? filename + 1 : path;
}

void *cita_linux_malloc(size_t size, const char *filename, const char *func, int line)
{
  // Record the caller while allocating under the shared lock
  CITA_LOCK
  ADD_CITA_INFO
  void *ptr = cita_malloc(size);
  RESET_CITA_INFO
  CITA_UNLOCK
  return ptr;
}

void cita_linux_free(void *ptr, const char *filename, const char *func, int line)
{
  // Record the caller while freeing under the shared lock
  CITA_LOCK
  ADD_CITA_INFO
  cita_free(ptr);
  RESET_CITA_INFO
  CITA_UNLOCK
}

void *cita_linux_calloc(size_t nmemb, size_t size, const char *filename, const char *func, int line)
{
  // Record the caller while zeroing a new allocation under the shared lock
  CITA_LOCK
  ADD_CITA_INFO
  void *ptr = cita_calloc(nmemb, size);
  RESET_CITA_INFO
  CITA_UNLOCK
  return ptr;
}

void *cita_linux_realloc(void *ptr, size_t size, const char *filename, const char *func, int line)
{
  // Record the caller while resizing under the shared lock
  CITA_LOCK
  ADD_CITA_INFO
  void *new_ptr = cita_realloc(ptr, size);
  RESET_CITA_INFO
  CITA_UNLOCK
  return new_ptr;
}

size_t cita_linux_alloc_enough_pattern(void **buffer, size_t needed_count, size_t alloc_count,
  size_t size_elem, double inc_ratio, uint8_t pattern, const char *filename, const char *func, int line)
{
  // Grow and label the buffer only when its current capacity is insufficient
  if (needed_count > alloc_count)
  {
    size_t new_count = (size_t) ((double) needed_count * inc_ratio + 0.9999999999999999);
    if (new_count < needed_count || size_elem == 0 || new_count > SIZE_MAX / size_elem)
    {
      CITA_REPORT("cita_linux_alloc_enough_pattern(): invalid allocation size");
      return alloc_count;
    }

    CITA_LOCK
    ADD_CITA_INFO
    void *new_buffer = cita_realloc(*buffer, new_count * size_elem);
    RESET_CITA_INFO
    CITA_UNLOCK
    if (!new_buffer)
    {
      CITA_REPORT("cita_linux_alloc_enough_pattern(): allocation failed");
      return alloc_count;
    }

    // Initialize the newly available elements and publish the new capacity
    *buffer = new_buffer;
    memset((uint8_t *) new_buffer + alloc_count * size_elem, pattern,
      (new_count - alloc_count) * size_elem);
    alloc_count = new_count;
  }
  return alloc_count;
}

#endif // CITA_LINUX_IMPLEMENTATION
