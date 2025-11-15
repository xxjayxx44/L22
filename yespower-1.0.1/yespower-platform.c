#ifdef __unix__
#include <sys/mman.h>
#endif

/* ULTRA-FAST MEMORY ALLOCATION FOR MINING */
/* REDUCED THRESHOLD FOR HUGE PAGES - FASTER MEMORY ACCESS */
#define HUGEPAGE_THRESHOLD		(2 * 1024 * 1024)  // Was 12MB, now 2MB

#ifdef __x86_64__
#define HUGEPAGE_SIZE			(2 * 1024 * 1024)
#else
#undef HUGEPAGE_SIZE
#endif

/* THREAD-LOCAL CACHE FOR MINING - AVOID REPEATED ALLOCATIONS */
static __thread void *mining_cache = NULL;
static __thread size_t mining_cache_size = 0;

/* ULTRA-FAST REGION ALLOCATION - OPTIMIZED FOR MINING WORKLOAD */
static void *alloc_region(yespower_region_t *region, size_t size)
{
    size_t base_size = size;
    uint8_t *base, *aligned;
    
    /* CHECK THREAD-LOCAL CACHE FIRST */
    if (mining_cache && mining_cache_size >= size) {
        base = aligned = mining_cache;
        base_size = mining_cache_size;
        mining_cache = NULL;  // Take ownership
        mining_cache_size = 0;
        goto success;
    }

#ifdef MAP_ANON
    int flags = MAP_ANON | MAP_PRIVATE;
    
    /* USE HUGE PAGES MORE AGGRESSIVELY FOR BETTER PERFORMANCE */
#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
    if (size >= HUGEPAGE_THRESHOLD) {
        flags |= MAP_HUGETLB;
        const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE - 1;
        base_size = (size + hugepage_mask) & ~hugepage_mask;
        
        /* TRY HUGE PAGES FIRST */
        base = mmap(NULL, base_size, PROT_READ | PROT_WRITE, flags, -1, 0);
        if (base != MAP_FAILED) {
            goto mapped;
        }
        /* FALLBACK TO REGULAR PAGES */
        flags &= ~MAP_HUGETLB;
        base_size = size;
    }
#endif

    /* REGULAR MMAP */
    base = mmap(NULL, base_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (base == MAP_FAILED) {
        base = NULL;
        goto done;
    }

#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
mapped:
#endif

    /* OPTIMIZE MEMORY FOR MINING - SEQUENTIAL ACCESS PATTERN */
#ifdef MADV_SEQUENTIAL
    if (base && base_size >= HUGEPAGE_THRESHOLD) {
        madvise(base, base_size, MADV_SEQUENTIAL | MADV_WILLNEED);
    }
#endif

#elif defined(HAVE_POSIX_MEMALIGN)
    /* FAST POSIX_MEMALIGN PATH */
    if (posix_memalign((void **)&base, 64, size) != 0) {
        base = NULL;
    }
#else
    /* SIMPLE MALLOC FALLBACK */
    base = malloc(size + 63);
    if (base) {
        base = (uint8_t *)(((uintptr_t)base + 63) & ~(uintptr_t)63);
    }
#endif

done:
    aligned = base;

success:
    region->base = base;
    region->aligned = aligned;
    region->base_size = base ? base_size : 0;
    region->aligned_size = base ? size : 0;
    
    /* PREFAULT PAGES FOR ZERO LATENCY DURING MINING */
    if (base && base_size >= (1 << 20)) { // 1MB or larger
        volatile uint8_t *p = base;
        for (size_t i = 0; i < base_size; i += 4096) {
            p[i] = 0;
        }
    }
    
    return aligned;
}

/* CACHE-AWARE REGION INITIALIZATION */
static inline void init_region(yespower_region_t *region)
{
    /* PRESERVE CACHE IF POSSIBLE, JUST MARK AS AVAILABLE */
    if (region->base && region->base_size > 0) {
        /* KEEP THE MEMORY BUT MARK AS UNUSED FOR REUSE */
        return;
    }
    region->base = region->aligned = NULL;
    region->base_size = region->aligned_size = 0;
}

/* OPTIMIZED REGION FREE - CACHE FOR REUSE */
static int free_region(yespower_region_t *region)
{
    if (region->base) {
        /* CACHE LARGE ALLOCATIONS FOR REUSE */
        if (region->base_size >= (1 << 20)) { // Cache allocations >1MB
            if (!mining_cache || region->base_size > mining_cache_size) {
                /* FREE OLD CACHE IF EXISTS */
                if (mining_cache) {
#ifdef MAP_ANON
                    munmap(mining_cache, mining_cache_size);
#else
                    free(mining_cache);
#endif
                }
                /* CACHE THIS ALLOCATION */
                mining_cache = region->base;
                mining_cache_size = region->base_size;
                
                /* CLEAR CACHED MEMORY FOR NEXT USE */
                memset(region->base, 0, region->base_size);
                
                /* REINIT REGION WITHOUT ACTUALLY FREEING */
                init_region(region);
                return 0;
            }
        }
        
        /* ACTUALLY FREE SMALL ALLOCATIONS */
#ifdef MAP_ANON
        if (munmap(region->base, region->base_size)) {
            return -1;
        }
#else
        free(region->base);
#endif
    }
    init_region(region);
    return 0;
}

/* MINING-SPECIFIC OPTIMIZATIONS */

/* DIRECT HUGE PAGE ALLOCATION FOR MINING WORKLOAD */
static void *alloc_mining_buffer(size_t size)
{
#ifdef MAP_ANON
#if defined(MAP_HUGETLB) && defined(HUGEPAGE_SIZE)
    int flags = MAP_ANON | MAP_PRIVATE | MAP_HUGETLB;
    const size_t hugepage_mask = (size_t)HUGEPAGE_SIZE - 1;
    size_t alloc_size = (size + hugepage_mask) & ~hugepage_mask;
    
    void *buf = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (buf != MAP_FAILED) {
        /* OPTIMIZE FOR SEQUENTIAL ACCESS */
#ifdef MADV_SEQUENTIAL
        madvise(buf, alloc_size, MADV_SEQUENTIAL | MADV_WILLNEED);
#endif
        return buf;
    }
#endif
    /* FALLBACK TO REGULAR PAGES */
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
#else
    return aligned_alloc(64, size);
#endif
}

/* FAST BULK MEMORY ZEROING - OPTIMIZED FOR MINING */
static inline void fast_zero_memory(void *ptr, size_t size)
{
    /* USE MEMSET FOR LARGE BLOCKS, COMPILER WILL OPTIMIZE */
    if (size >= 4096) {
        memset(ptr, 0, size);
    } else {
        /* SMALL BLOCKS - MANUAL ZEROING MAY BE FASTER */
        uint64_t *p64 = (uint64_t *)ptr;
        size_t count64 = size / 8;
        for (size_t i = 0; i < count64; i++) {
            p64[i] = 0;
        }
        /* HANDLE REMAINDER */
        uint8_t *p8 = (uint8_t *)ptr + count64 * 8;
        for (size_t i = count64 * 8; i < size; i++) {
            p8[i] = 0;
        }
    }
}

/* MINING WORKER MEMORY MANAGEMENT */
typedef struct {
    void *buffers[4];
    size_t sizes[4];
    int count;
} mining_memory_pool_t;

static __thread mining_memory_pool_t memory_pool = {0};

/* GET CACHED MINING BUFFER */
static void *get_mining_buffer(size_t size)
{
    for (int i = 0; i < memory_pool.count; i++) {
        if (memory_pool.sizes[i] >= size) {
            void *buf = memory_pool.buffers[i];
            memory_pool.buffers[i] = NULL;
            return buf;
        }
    }
    return alloc_mining_buffer(size);
}

/* RETURN BUFFER TO POOL FOR REUSE */
static void return_mining_buffer(void *buf, size_t size)
{
    for (int i = 0; i < memory_pool.count; i++) {
        if (memory_pool.buffers[i] == NULL) {
            memory_pool.buffers[i] = buf;
            memory_pool.sizes[i] = size;
            return;
        }
    }
    /* POOL FULL - FREE IT */
#ifdef MAP_ANON
    munmap(buf, size);
#else
    free(buf);
#endif
}
