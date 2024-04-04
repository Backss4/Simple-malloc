//
// Created by root on 10/6/23.
//

#include "heap.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "custom_unistd.h"


#define PAGE_SIZE 4096
#define FENCE_SIZE 16
#define WORD_SIZE sizeof(void *)

const uint8_t FENCE_BYTES[] = {0xf5, 0x83, 0xde, 0x0f, 0x0d, 0xc7, 0xb6, 0xb5, 0xc7, 0x49, 0x75, 0x58, 0x5b, 0xce, 0x2f,
                               0x80};
//const uint8_t BACK_MAGIC_BYTES[] = {0x65, 0x18, 0x23, 0xbe, 0x1b, 0xe2, 0x51, 0x95, 0xb8, 0xc9, 0x66, 0x57, 0xda, 0xb2, 0xa2, 0xa6};

#define MAGIC1 0x4862b14310a08ec4
#define MAGIC2 0x1efb2c41b1dbf9ce
#define MAGIC3 0x123BAC55

#define SBRK_ERROR ((void *) -1)


typedef enum heap_validate_error {
    HEAP_VALIDATE_OK = 0,
    HEAP_VALIDATE_FENCE_ERROR,
    HEAP_VALIDATE_UNINITIALIZED,
    HEAP_VALIDATE_INTEGRITY_ERROR
} heap_validate_error_t;

typedef struct mem_block {
    uint64_t magic1;
    struct mem_block *next;
    struct mem_block *prev;
    size_t size;
    int line;
    const char *file;
    uint32_t checksum;
    uint64_t magic2;
} mem_block_t;

typedef struct heap_manager {
    void *start_brk;
    void *current_brk;
    struct mem_block *head;
} heap_manager_t;

typedef void *(*malloc_func_t)(size_t);


#define ALIGN_UP(size, to)      (((size) + (to) - 1) & -((__typeof__ (size)) (to)))
#define PTR_ALIGN_UP(base, to)  ((__typeof__ (base)) ALIGN_UP((uintptr_t) (base), (to)))

#define REAL_SIZE(size)         (ALIGN_UP((size) + sizeof(mem_block_t) + FENCE_SIZE * 2, WORD_SIZE))

#define NEXT_BLOCK(block)       (block->next)
#define PREV_BLOCK(block)       (block->prev)

static heap_manager_t heap_manager = {.start_brk = NULL, .current_brk = NULL, .head = NULL};
static bool initialized = false;

/*===  INTERNAL FUNCTIONS:  START   ===*/

//declarations

void *heap_realloc_internal(void *, size_t, malloc_func_t);

void *heap_calloc_internal(size_t, size_t, malloc_func_t);

//helpers start
static uint32_t checksum(const void *restrict, size_t);

static inline int check_block_fit(const void *, const void *, size_t);
//helpers end

//pointer helpers start
static inline void *get_header_ptr(void *addr);

static inline void *get_front_fence_ptr(const mem_block_t *);

static inline void *get_tail_fence_ptr(const mem_block_t *);

static inline void *get_user_ptr(const mem_block_t *);

static inline void *get_after_ptr(const mem_block_t *);

//pointer helpers end

//mem block helpers start
static void mem_block_init(mem_block_t *, mem_block_t *, mem_block_t *, size_t);

static inline void mem_block_update_chks(mem_block_t *);

static heap_validate_error_t mem_block_validate(const mem_block_t *);

static inline size_t mem_block_size(const mem_block_t *);

static inline void mem_block_add_debug_info(mem_block_t *, int, const char *);
//mem block helpers end

//mem block list start
static mem_block_t *mem_block_insert(mem_block_t *, size_t);

static mem_block_t *mem_block_insert_aligned(mem_block_t *, size_t, uintptr_t);

static void mem_block_delete(mem_block_t *);
//mem block list end

//definitions

void *heap_realloc_internal(void *memblock, size_t size, malloc_func_t malloc_func) {
    assert(malloc_func != NULL);
    enum pointer_type_t pointer_t = get_pointer_type(memblock);
    if ((memblock == NULL && size == 0) || (pointer_t != pointer_null && pointer_t != pointer_valid))
        return NULL;

    if (pointer_t == pointer_null)
        return malloc_func(size);

    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }

    mem_block_t *block = get_header_ptr(memblock);
    if (size == block->size)
        return memblock;

    if (size < block->size) {
        block->size = size;
        mem_block_update_chks(block);
        memcpy(get_tail_fence_ptr(block), FENCE_BYTES, FENCE_SIZE);
        return memblock;
    }

    if (NEXT_BLOCK(block) != NULL
        && check_block_fit(get_after_ptr(block), NEXT_BLOCK(block), size - mem_block_size(block)) == 0) {
        block->size = size;
        memcpy(get_tail_fence_ptr(block), FENCE_BYTES, FENCE_SIZE);
        mem_block_update_chks(block);
        return memblock;
    } else {
        if (NEXT_BLOCK(block) == NULL) {
            if (check_block_fit(get_after_ptr(block), heap_manager.current_brk, size - mem_block_size(block))) {
                if (custom_sbrk(ALIGN_UP(size - block->size, PAGE_SIZE)) == SBRK_ERROR) {
                    return NULL;
                }
                heap_manager.current_brk =
                        (int8_t *) heap_manager.current_brk + ALIGN_UP(size - block->size, PAGE_SIZE);
            }
            block->size = size;
            memcpy(get_tail_fence_ptr(block), FENCE_BYTES, FENCE_SIZE);
            mem_block_update_chks(block);
            return memblock;
        }
        mem_block_t *new_block = malloc_func(size);
        if (new_block == NULL)
            return NULL;
        memcpy(new_block, memblock, block->size);
        heap_free(memblock);
        return new_block;
    }
}

void *heap_calloc_internal(size_t number, size_t size, malloc_func_t malloc_func) {
    assert(malloc_func != NULL);
    void *block = malloc_func(number * size);
    if (block == NULL)
        return NULL;
    memset(block, 0, number * size);
    return block;
}

//helpers start
uint32_t checksum(const void *restrict buf, size_t size) {
    assert(buf != NULL);
    uint32_t checksum = 0;
    const uint8_t *restrict ptr = (const uint8_t *restrict) buf;
    while (size--) {
        checksum = (checksum ^ *ptr++) ^ MAGIC3;
    }
    return checksum;
}

int check_block_fit(const void *from, const void *to, size_t size) {
    assert(from != NULL && to != NULL && from <= to);
    return (uintptr_t) to - (uintptr_t) from < REAL_SIZE(size);
}
//helpers end

//pointer helpers start
void *get_header_ptr(void *addr) {
    return (int8_t *) addr - FENCE_SIZE - sizeof(mem_block_t);
}

void *get_front_fence_ptr(const mem_block_t *block) {
    return (int8_t *) block + sizeof(mem_block_t);
}

void *get_tail_fence_ptr(const mem_block_t *block) {
    return (int8_t *) block + sizeof(mem_block_t) + FENCE_SIZE + block->size;
}

void *get_user_ptr(const mem_block_t *block) {
    return (int8_t *) block + sizeof(mem_block_t) + FENCE_SIZE;
}

void *get_after_ptr(const mem_block_t *block) {
    return (int8_t *) block + mem_block_size(block);
}

//pointer helpers end

//mem block helpers start
void mem_block_init(mem_block_t *block, mem_block_t *prev, mem_block_t *next, size_t size) {
    block->magic1 = MAGIC1;
    block->magic2 = MAGIC2;
    block->size = size;
    block->prev = prev;
    block->next = next;
    block->line = 0;
    block->file = NULL;
    mem_block_update_chks(block);
    memcpy(get_front_fence_ptr(block), FENCE_BYTES, FENCE_SIZE);
    memcpy(get_tail_fence_ptr(block), FENCE_BYTES, FENCE_SIZE);
    if (next != NULL) {
        PREV_BLOCK(next) = block;
        mem_block_update_chks(next);
    }
    if (prev != NULL) {
        NEXT_BLOCK(prev) = block;
        mem_block_update_chks(prev);
    }
}

heap_validate_error_t mem_block_validate(const mem_block_t *block) {
    if (block->magic1 != MAGIC1 || block->magic2 != MAGIC2)
        return HEAP_VALIDATE_INTEGRITY_ERROR;

    mem_block_t temp = *block;
    temp.checksum = 0;
    if (checksum(&temp, sizeof(mem_block_t)) != block->checksum)
        return HEAP_VALIDATE_INTEGRITY_ERROR;

    if (memcmp(get_front_fence_ptr(block), FENCE_BYTES, FENCE_SIZE) != 0)
        return HEAP_VALIDATE_FENCE_ERROR;

    if (memcmp(get_tail_fence_ptr(block), FENCE_BYTES, FENCE_SIZE) != 0)
        return HEAP_VALIDATE_FENCE_ERROR;

    return HEAP_VALIDATE_OK;
}

void mem_block_update_chks(mem_block_t *block) {
    block->checksum = 0;
    block->checksum = checksum(block, sizeof(mem_block_t));
}

size_t mem_block_size(const mem_block_t *block) {
    return REAL_SIZE(block->size);
}

void mem_block_add_debug_info(mem_block_t *block, int line, const char *file) {
    block->file = file;
    block->line = line;
    mem_block_update_chks(block);
}
//mem block helpers end

mem_block_t *mem_block_insert(mem_block_t *after, size_t size) {
    mem_block_t *block = NULL;
    if (after == NULL) {
        block = heap_manager.start_brk;
        mem_block_init(block, NULL, heap_manager.head, size);
        heap_manager.head = block;
        return block;
    }
    block = get_after_ptr(after);
    mem_block_init(block, after, after->next, size);
    return block;
}

mem_block_t *mem_block_insert_aligned(mem_block_t *after, size_t size, uintptr_t offset) {
    mem_block_t *block = NULL;
    if (after == NULL) {
        block = (void *) ((uint8_t *) heap_manager.start_brk + offset - sizeof(mem_block_t) - FENCE_SIZE);
        mem_block_init(block, NULL, heap_manager.head, size);
        heap_manager.head = block;
        return block;
    }
    block = (void *) (PTR_ALIGN_UP((uint8_t *) get_after_ptr(after), PAGE_SIZE) + offset - sizeof(mem_block_t) -
                      FENCE_SIZE);
    mem_block_init(block, after, NEXT_BLOCK(after), size);
    return block;
}

void mem_block_delete(mem_block_t *block) {
    assert(block != NULL);

    if (block == heap_manager.head) {
        assert(PREV_BLOCK(block) == NULL);
        heap_manager.head = NEXT_BLOCK(block);
        if (NEXT_BLOCK(block) != NULL) {
            NEXT_BLOCK(block)->prev = NULL;
            mem_block_update_chks(heap_manager.head);
        }
        return;
    }

    assert(PREV_BLOCK(block) != NULL);
    PREV_BLOCK(block)->next = NEXT_BLOCK(block);
    if (NEXT_BLOCK(block) != NULL) {
        NEXT_BLOCK(block)->prev = PREV_BLOCK(block);
        mem_block_update_chks(NEXT_BLOCK(block));
    }
    mem_block_update_chks(PREV_BLOCK(block));
}

/*===  INTERNAL FUNCTIONS:  END     ===*/


// API

int heap_setup(void) {
    int8_t *cur_brk = custom_sbrk(PAGE_SIZE);
    if (cur_brk == SBRK_ERROR)
        return 1;
    heap_manager.start_brk = cur_brk;
    heap_manager.current_brk = cur_brk + PAGE_SIZE;
    heap_manager.head = NULL;
    initialized = 1;
    return 0;
}

void heap_clean(void) {
    initialized = 0;
    ptrdiff_t mem_delta = (int8_t *) heap_manager.start_brk - (int8_t *) heap_manager.current_brk;
    custom_sbrk(mem_delta);
    heap_manager.start_brk = NULL;
    heap_manager.current_brk = NULL;
    heap_manager.head = NULL;
}

void *heap_malloc(size_t size) {
    if (size == 0 || heap_validate())
        return NULL;

    mem_block_t *block = NULL;
    mem_block_t *last = heap_manager.head;
    if (heap_manager.head == NULL) {
        if (check_block_fit(heap_manager.start_brk, heap_manager.current_brk, size)) {
            if (custom_sbrk(ALIGN_UP(REAL_SIZE(size), PAGE_SIZE)) == SBRK_ERROR) {
                return NULL;
            }
            heap_manager.current_brk = (int8_t *) heap_manager.current_brk + ALIGN_UP(REAL_SIZE(size), PAGE_SIZE);
        }
        block = mem_block_insert(NULL, size);
        return get_user_ptr(block);
    }

    if (heap_manager.head != heap_manager.start_brk &&
        check_block_fit(heap_manager.start_brk, heap_manager.head, size) == 0) {
        block = mem_block_insert(NULL, size);
        return get_user_ptr(block);
    }

    for (mem_block_t *current = last; current != NULL; current = NEXT_BLOCK(current)) {
        last = current;
        if (NEXT_BLOCK(current) != NULL &&
            check_block_fit(get_after_ptr(current), NEXT_BLOCK(current), size) == 0) {
            block = mem_block_insert(current, size);
            return get_user_ptr(block);
        }
    }
    assert(last != NULL && block == NULL);
    if (check_block_fit(get_after_ptr(last), heap_manager.current_brk, size)) {
        if (custom_sbrk(ALIGN_UP(REAL_SIZE(size), PAGE_SIZE)) == SBRK_ERROR) {
            return NULL;
        }
        heap_manager.current_brk = (int8_t *) heap_manager.current_brk + ALIGN_UP(REAL_SIZE(size), PAGE_SIZE);
    }
    block = mem_block_insert(last, size);
    return get_user_ptr(block);
}

void *heap_calloc(size_t number, size_t size) {
    return heap_calloc_internal(number, size, heap_malloc);
}

void *heap_realloc(void *memblock, size_t size) {
    return heap_realloc_internal(memblock, size, heap_malloc);
}

void *heap_malloc_aligned(size_t size) {
    if (size == 0 || heap_validate())
        return NULL;

    mem_block_t *block = NULL;
    mem_block_t *last = heap_manager.head;
    uintptr_t offset = PAGE_SIZE;
    if (heap_manager.head == NULL) {
        if (custom_sbrk(ALIGN_UP(REAL_SIZE(size), PAGE_SIZE)) == SBRK_ERROR) {
            return NULL;
        }
        heap_manager.current_brk = (int8_t *) heap_manager.current_brk + ALIGN_UP(REAL_SIZE(size), PAGE_SIZE);
        block = mem_block_insert_aligned(NULL, size, offset);
        return get_user_ptr(block);
    }

    if (heap_manager.head != heap_manager.start_brk
        && (uint8_t *) heap_manager.start_brk + PAGE_SIZE - sizeof(mem_block_t) - FENCE_SIZE <
           (uint8_t *) heap_manager.head
        && check_block_fit((uint8_t *) heap_manager.start_brk + PAGE_SIZE - sizeof(mem_block_t) - FENCE_SIZE,
                           heap_manager.head, size) == 0) {
        block = mem_block_insert_aligned(NULL, size, offset);
        return get_user_ptr(block);
    }

    for (mem_block_t *current = last; current != NULL; current = NEXT_BLOCK(current)) {
        last = current;
        if (NEXT_BLOCK(current) != NULL) {
            offset = PAGE_SIZE;
            if (ALIGN_UP((uintptr_t) get_after_ptr(current), PAGE_SIZE) - (uintptr_t) get_after_ptr(current) >=
                sizeof(mem_block_t) + FENCE_SIZE) {
                offset = 0;
            }
            if (PTR_ALIGN_UP((uint8_t *) get_after_ptr(current), PAGE_SIZE) + offset - sizeof(mem_block_t) -
                FENCE_SIZE < (uint8_t *) NEXT_BLOCK(current)
                && check_block_fit(
                    PTR_ALIGN_UP((uint8_t *) get_after_ptr(current), PAGE_SIZE) + offset - sizeof(mem_block_t) -
                    FENCE_SIZE, NEXT_BLOCK(current), size) == 0) {
                block = mem_block_insert_aligned(current, size, offset);
                return get_user_ptr(block);
            }
        }
    }
    assert(last != NULL && block == NULL);
    offset = PAGE_SIZE;
    if (ALIGN_UP((uintptr_t) get_after_ptr(last), PAGE_SIZE) - (uintptr_t) get_after_ptr(last) >=
        sizeof(mem_block_t) + FENCE_SIZE) {
        offset = 0;
    }
    if (PTR_ALIGN_UP((uint8_t *) get_after_ptr(last), PAGE_SIZE) + offset - sizeof(mem_block_t) - FENCE_SIZE >
        (uint8_t *) heap_manager.current_brk
        || check_block_fit(
            PTR_ALIGN_UP((uint8_t *) get_after_ptr(last), PAGE_SIZE) + offset - sizeof(mem_block_t) - FENCE_SIZE,
            (uint8_t *) heap_manager.current_brk, size)) {
        if (custom_sbrk(ALIGN_UP(REAL_SIZE(size), PAGE_SIZE) + offset) == SBRK_ERROR) {
            return NULL;
        }
        heap_manager.current_brk = (int8_t *) heap_manager.current_brk + offset + ALIGN_UP(REAL_SIZE(size), PAGE_SIZE);
    }
    block = mem_block_insert_aligned(last, size, offset);
    return get_user_ptr(block);
}

void *heap_calloc_aligned(size_t number, size_t size) {
    return heap_calloc_internal(number, size, heap_malloc_aligned);
}

void *heap_realloc_aligned(void *memblock, size_t size) {
    return heap_realloc_internal(memblock, size, heap_malloc_aligned);
}

void heap_free(void *memblock) {
    if (get_pointer_type(memblock) != pointer_valid)
        return;

    mem_block_delete(get_header_ptr(memblock));
}

int heap_validate(void) {
    if (!initialized)
        return HEAP_VALIDATE_UNINITIALIZED;
    for (const mem_block_t *i = heap_manager.head; i != NULL; i = i->next) {
        heap_validate_error_t err = mem_block_validate(i);
        if (err != HEAP_VALIDATE_OK) {
            return err;
        }
    }
    return HEAP_VALIDATE_OK;
}

size_t heap_get_largest_used_block_size(void) {
    if (heap_validate())
        return 0;
    size_t max = 0;
    for (const mem_block_t *i = heap_manager.head; i != NULL; i = i->next) {
        if (max < i->size) {
            max = i->size;
        }
    }
    return max;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (pointer == NULL)
        return pointer_null;

    if (heap_validate())
        return pointer_heap_corrupted;

    if ((int8_t *) pointer < (int8_t *) heap_manager.start_brk ||
        (int8_t *) pointer > (int8_t *) heap_manager.current_brk)
        return pointer_unallocated;

    for (const mem_block_t *current = heap_manager.head; current != NULL; current = current->next) {
        if ((int8_t *) pointer == (int8_t *) get_user_ptr(current))
            return pointer_valid;
        if ((int8_t *) pointer > (int8_t *) get_user_ptr(current) &&
            (int8_t *) pointer < (int8_t *) get_tail_fence_ptr(current))
            return pointer_inside_data_block;
        if ((mem_block_t *) pointer >= current && (mem_block_t *) pointer < current + 1)
            return pointer_control_block;
        if ((int8_t *) pointer >= (int8_t *) get_front_fence_ptr(current)
            && (int8_t *) pointer < (int8_t *) get_front_fence_ptr(current) + FENCE_SIZE)
            return pointer_inside_fences;
        if ((int8_t *) pointer >= (int8_t *) get_tail_fence_ptr(current)
            && (int8_t *) pointer < (int8_t *) get_tail_fence_ptr(current) + FENCE_SIZE)
            return pointer_inside_fences;
    }

    return pointer_unallocated;
}

void *heap_malloc_debug(size_t size, int fileline, const char *filename) {
    void *mem = heap_malloc(size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

void *heap_calloc_debug(size_t number, size_t size, int fileline, const char *filename) {
    void *mem = heap_calloc(number, size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

void *heap_realloc_debug(void *memblock, size_t size, int fileline, const char *filename) {
    void *mem = heap_realloc(memblock, size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

void *heap_malloc_aligned_debug(size_t size, int fileline, const char *filename) {
    void *mem = heap_malloc_aligned(size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

void *heap_calloc_aligned_debug(size_t number, size_t size, int fileline, const char *filename) {
    void *mem = heap_calloc_aligned(number, size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

void *heap_realloc_aligned_debug(void *memblock, size_t size, int fileline, const char *filename) {
    void *mem = heap_realloc_aligned(memblock, size);
    if(mem != NULL) {
        mem_block_add_debug_info(get_header_ptr(mem), fileline, filename);
    }
    return mem;
}

