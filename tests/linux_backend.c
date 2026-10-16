#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CITA_OS_MAX ((size_t) 256 << 20)
#define CITA_OS_IMPLEMENTATION
#include "../cita_os.h"

static void *exercise_thread(void *unused)
{
  // Exercise allocation and resizing while other threads use the same heap
  (void) unused;
  for (int i = 0; i < 100; i++)
  {
    uint8_t *buffer = malloc(32);
    assert(buffer);
    memset(buffer, i, 32);
    buffer = realloc(buffer, 128);
    assert(buffer);
    for (int j = 0; j < 32; j++)
      assert(buffer[j] == i);
    free(buffer);
  }
  return NULL;
}

int main(void)
{
  // Check zeroed allocation, caller metadata, and normal resizing
  uint8_t *buffer = calloc(64, 1);
  assert(buffer);
  for (int i = 0; i < 64; i++)
    assert(buffer[i] == 0);
  assert(cita_buffer.mem && memcmp(cita_buffer.mem, "CITA", 4) == 0);
  CITA_INDEX_TYPE index = cita_table_find_buffer((uintptr_t) buffer, 1);
  assert(index != NAI);
  assert(strstr(ct->elem[index].extra.info, "linux_backend.c"));
  buffer = realloc(buffer, 128);
  assert(buffer);
  free(buffer);

  // Check the platform wrapper used by alloc_enough
  void *growth = NULL;
  size_t capacity = 0;
  alloc_enough(&growth, 10, &capacity, sizeof(uint32_t), 1.5);
  assert(growth && capacity >= 10);
  free(growth);

  // Confirm independent threads can share the backend lock
  pthread_t threads[4];
  for (int i = 0; i < 4; i++)
    assert(pthread_create(&threads[i], NULL, exercise_thread, NULL) == 0);
  for (int i = 0; i < 4; i++)
    assert(pthread_join(threads[i], NULL) == 0);

  // Trigger tail decommit and then recommit the same address range
  size_t before = (size_t) (cita_buffer.mem_end - (uintptr_t) cita_buffer.mem);
  uint8_t *large = malloc((size_t) 64 << 20);
  assert(large);
  memset(large, 0x5A, (size_t) 64 << 20);
  size_t grown = (size_t) (cita_buffer.mem_end - (uintptr_t) cita_buffer.mem);
  assert(grown > before + ((size_t) 32 << 20));
  free(large);
  size_t shrunk = (size_t) (cita_buffer.mem_end - (uintptr_t) cita_buffer.mem);
#ifdef __CYGWIN__
  // MSYS does not implement Linux madvise reclamation, so retain the committed tail
  assert(shrunk == grown);
#else
  // Linux should release a sufficiently large unused tail
  assert(shrunk < grown);
#endif
  large = malloc((size_t) 64 << 20);
  assert(large);
  memset(large, 0xA5, (size_t) 64 << 20);
  free(large);

  puts("CITA Linux backend tests passed");
  return 0;
}
