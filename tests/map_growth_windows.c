#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CITA_REPORT_TO_STDERR
#define CITA_INIT_ELEM_AS 4
#define CITA_WIN_IMPLEMENTATION
#include "../cita_windows.h"

#ifndef CITA_MAP_SCALE
#error CITA_MAP_SCALE must be enabled for this regression test
#endif

static size_t test_map_needed_count(void)
{
	return (size_t) ((CITA_MEM_END - CITA_MEM_START + CITA_MAP_CELL_SIZE - 1) >> CITA_MAP_SCALE);
}

static int test_validate_map(const char *label)
{
	size_t needed = test_map_needed_count();
	CITA_INDEX_TYPE *map = CITA_PTR(ct->elem[2].addr);

	if (cita_map_count < needed)
	{
		fprintf(stderr, "%s: map has %zu cells but needs %zu\n", label, cita_map_count, needed);
		return 1;
	}

	for (size_t i=0; i < needed; i++)
	{
		CITA_INDEX_TYPE index = map[i];
		if (index != NAI && (index >= ct->elem_count || ct->elem[index].next_index == NAI))
		{
			fprintf(stderr, "%s: map[%zu] contains invalid index %u\n", label, i, (unsigned) index);
			return 1;
		}

		if (index != NAI)
		{
			CITA_ADDR_TYPE cell_start = CITA_MEM_START + (CITA_ADDR_TYPE) i * CITA_MAP_CELL_SIZE;
			CITA_ADDR_TYPE cell_end = cell_start + CITA_MAP_CELL_SIZE;
			if (!(ct->elem[index].addr < cell_end && cell_start < ct->elem[index].addr_end))
			{
				fprintf(stderr, "%s: map[%zu] contains non-overlapping index %u\n", label, i, (unsigned) index);
				return 1;
			}
		}
	}

	return 0;
}

int main(void)
{
	char *a = malloc(100000);
	char *b = malloc(50000);

	if (a == NULL || b == NULL)
		return 1;

	memset(a, 0x11, 100000);
	memset(b, 0x22, 50000);

	if (test_validate_map("after initial allocations"))
		return 1;

	a = realloc(a, 200000);
	if (a == NULL)
		return 1;

	if (test_validate_map("after growing realloc"))
		return 1;

	free(b);

	if (test_validate_map("after freeing neighbor"))
		return 1;

	char *c = malloc(250000);
	if (c == NULL)
		return 1;

	c = realloc(c, 4096);
	if (c == NULL)
		return 1;

	if (test_validate_map("after shrinking tail allocation"))
		return 1;

	char *d = malloc(16000);
	if (d == NULL)
		return 1;

	if (test_validate_map("after allocating into shrunken tail"))
		return 1;

	int32_t index = cita_table_find_buffer((CITA_ADDR_TYPE) (a + 90000), 0);
	if (index < 0)
	{
		fprintf(stderr, "lookup inside reallocated buffer failed\n");
		return 1;
	}

	free(d);
	free(c);
	free(a);

	return test_validate_map("after final free");
}
