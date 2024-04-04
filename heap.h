//
// Created by root on 10/6/23.
//

#ifndef PROJEKT_ALOKATOR_HEAP_H
#define PROJEKT_ALOKATOR_HEAP_H

#include <stdint.h>
#include <stddef.h>


enum pointer_type_t {
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};


int heap_setup(void);

void heap_clean(void);

void *heap_malloc(size_t size);

void *heap_calloc(size_t number, size_t size);

void *heap_realloc(void *memblock, size_t size);

void *heap_malloc_aligned(size_t size);

void *heap_calloc_aligned(size_t number, size_t size);

void *heap_realloc_aligned(void *memblock, size_t size);

void heap_free(void *memblock);

int heap_validate(void);

size_t heap_get_largest_used_block_size(void);

enum pointer_type_t get_pointer_type(const void *pointer);

void *heap_malloc_debug(size_t size, int fileline, const char *filename);

void *heap_calloc_debug(size_t number, size_t size, int fileline, const char *filename);

void *heap_realloc_debug(void *memblock, size_t size, int fileline, const char *filename);

void *heap_malloc_aligned_debug(size_t size, int fileline, const char *filename);

void *heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char *filename);

void *heap_realloc_aligned_debug(void *memblock, size_t size, int fileline, const char *filename);


#endif //PROJEKT_ALOKATOR_HEAP_H
