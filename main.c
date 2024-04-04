#include <stdio.h>
#include "heap.h"

#define PAGE_SIZE 4096

int test_heap_allocator() {
    void *ptr1 = heap_malloc(sizeof(char) * 140);
    void *ptr2 = heap_malloc(sizeof(char) * 140);
    void *ptr3 = heap_malloc(sizeof(char) * 140);
    heap_free(ptr2);
    void *ptr4 = heap_calloc(140, sizeof(char));
    if(ptr4 != ptr2) {
        return 1;
    }
    heap_free(ptr1);
    void *ptr5 = heap_realloc(NULL, sizeof(char) * 140);
    if(ptr5 != ptr1) {
        return 1;
    }
    void *ptr6 = heap_realloc(ptr3, sizeof(char) * 200);
    if(ptr6 != ptr3) {
        return 1;
    }
    heap_free(ptr1);
    heap_free(ptr2);
    heap_free(ptr3);
    heap_free(ptr4);
    heap_free(ptr5);
    heap_free(ptr6);
    if(heap_get_largest_used_block_size() != 0) {
        return 1;
    }
    return 0;
}

int test_heap_allocator_aligned() {
    void *ptr1 = heap_malloc_aligned(sizeof(char) * 140);
    void *ptr2 = heap_malloc_aligned(sizeof(char) * 140);
    void *ptr3 = heap_malloc_aligned(sizeof(char) * 140);
    if(((intptr_t)ptr1 & (intptr_t)(PAGE_SIZE - 1)) != 0) {
        return 1;
    }
    if(((intptr_t)ptr2 & (intptr_t)(PAGE_SIZE - 1)) != 0) {
        return 1;
    }
    if(((intptr_t)ptr3 & (intptr_t)(PAGE_SIZE - 1)) != 0) {
        return 1;
    }
    heap_free(ptr2);
    void *ptr4 = heap_calloc_aligned(140, sizeof(char));
    if(ptr4 != ptr2) {
        return 1;
    }
    heap_free(ptr1);
    void *ptr5 = heap_realloc_aligned(NULL, sizeof(char) * 140);
    if(ptr5 != ptr1) {
        return 1;
    }
    void *ptr6 = heap_realloc_aligned(ptr3, sizeof(char) * 200);
    if(ptr6 != ptr3) {
        return 1;
    }
    heap_free(ptr1);
    heap_free(ptr2);
    heap_free(ptr3);
    heap_free(ptr4);
    heap_free(ptr5);
    heap_free(ptr6);
    if(heap_get_largest_used_block_size() != 0) {
        return 1;
    }
    return 0;
}

int test_heap_allocator_debug() {
    void *ptr1 = heap_malloc_debug(sizeof(char) * 140, __LINE__, __FILE__);
    void *ptr2 = heap_malloc_debug(sizeof(char) * 140, __LINE__, __FILE__);
    void *ptr3 = heap_malloc_debug(sizeof(char) * 140, __LINE__, __FILE__);
    heap_free(ptr2);
    void *ptr4 = heap_calloc_debug(140, sizeof(char), __LINE__, __FILE__);
    if(ptr4 != ptr2) {
        return 1;
    }
    heap_free(ptr1);
    void *ptr5 = heap_realloc_debug(NULL, sizeof(char) * 140, __LINE__, __FILE__);
    if(ptr5 != ptr1) {
        return 1;
    }
    void *ptr6 = heap_realloc_debug(ptr3, sizeof(char) * 200, __LINE__, __FILE__);
    if(ptr6 != ptr3) {
        return 1;
    }
    heap_free(ptr1);
    heap_free(ptr2);
    heap_free(ptr3);
    heap_free(ptr4);
    heap_free(ptr5);
    heap_free(ptr6);
    if(heap_get_largest_used_block_size() != 0) {
        return 1;
    }
    return 0;
}

int test_heap_allocator_aligned_debug() {
    void *ptr1 = heap_malloc_aligned_debug(sizeof(char) * 140, __LINE__, __FILE__);
    void *ptr2 = heap_malloc_aligned_debug(sizeof(char) * 140, __LINE__, __FILE__);
    void *ptr3 = heap_malloc_aligned_debug(sizeof(char) * 140, __LINE__, __FILE__);
    heap_free(ptr2);
    void *ptr4 = heap_calloc_aligned_debug(140, sizeof(char), __LINE__, __FILE__);
    if(ptr4 != ptr2) {
        return 1;
    }
    heap_free(ptr1);
    void *ptr5 = heap_realloc_aligned_debug(NULL, sizeof(char) * 140, __LINE__, __FILE__);
    if(ptr5 != ptr1) {
        return 1;
    }
    void *ptr6 = heap_realloc_aligned_debug(ptr3, sizeof(char) * 200, __LINE__, __FILE__);
    if(ptr6 != ptr3) {
        return 1;
    }
    heap_free(ptr1);
    heap_free(ptr2);
    heap_free(ptr3);
    heap_free(ptr4);
    heap_free(ptr5);
    heap_free(ptr6);
    if(heap_get_largest_used_block_size() != 0) {
        return 1;
    }
    return 0;
}

int main() {
    heap_setup();
    if(test_heap_allocator()) {
        printf("Error in allocator heap_* functions");
    }
    if(test_heap_allocator_aligned()) {
        printf("Error in allocator heap_*_aligned functions");
    }
    if(test_heap_allocator_debug()) {
        printf("Error in allocator heap_*_debug functions");
    }
    if(test_heap_allocator_aligned_debug()) {
        printf("Error in allocator heap_*_aligned_debug functions");
    }
    heap_clean();
    return 0;
}
