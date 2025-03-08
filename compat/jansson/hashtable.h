#ifndef HASHTABLE_H
#define HASHTABLE_H

typedef unsigned int (*key_hash_fn)(const void *restrict key);
typedef int (*key_cmp_fn)(const void *restrict key1, const void *restrict key2);
typedef void (*free_fn)(void *restrict key);

struct hashtable_list {
    struct hashtable_list *restrict prev;
    struct hashtable_list *restrict next;
};

struct hashtable_pair {
    unsigned int hash;              /* Move hash first for alignment */
    void *restrict key;
    void *restrict value;
    struct hashtable_list list;
};

struct hashtable_bucket {
    struct hashtable_list *restrict first;
    struct hashtable_list *restrict last;
};

typedef struct hashtable {
    unsigned int size;
    unsigned int num_buckets;       /* index to primes[] */
    key_hash_fn hash_key;
    key_cmp_fn cmp_keys;            /* returns non-zero for equal keys */
    free_fn free_key;
    free_fn free_value;
    struct hashtable_bucket *restrict buckets;
    struct hashtable_list list;
} hashtable_t;

/* Create a new hashtable */
hashtable_t *hashtable_create(key_hash_fn hash_key, key_cmp_fn cmp_keys,
                              free_fn free_key, free_fn free_value);

/* Destroy a hashtable created with hashtable_create */
void hashtable_destroy(hashtable_t *restrict hashtable);

/* Initialize a statically allocated hashtable */
int hashtable_init(hashtable_t *restrict hashtable,
                   key_hash_fn hash_key, key_cmp_fn cmp_keys,
                   free_fn free_key, free_fn free_value);

/* Release resources used by a statically allocated hashtable */
void hashtable_close(hashtable_t *restrict hashtable);

/* Set a key/value pair in the hashtable; replaces existing value if key exists */
int hashtable_set(hashtable_t *restrict hashtable, void *restrict key, void *restrict value);

/* Retrieve a value associated with a key; returns NULL if not found */
void *hashtable_get(hashtable_t *restrict hashtable, const void *restrict key);

/* Remove a key/value pair from the hashtable; returns 0 on success, -1 if not found */
int hashtable_del(hashtable_t *restrict hashtable, const void *restrict key);

/* Clear all key/value pairs in the hashtable */
void hashtable_clear(hashtable_t *restrict hashtable);

/* Return an opaque iterator to the first element in the hashtable */
static inline void *hashtable_iter(hashtable_t *restrict hashtable)
{
    return hashtable ? (void *)hashtable->list.next : 0;
}

/* Return an iterator at a specific key */
void *hashtable_iter_at(hashtable_t *restrict hashtable, const void *restrict key);

/* Advance an iterator; returns next iterator or NULL if finished */
void *hashtable_iter_next(hashtable_t *restrict hashtable, void *iter);

/* Retrieve the key from an iterator */
static inline void *hashtable_iter_key(void *iter)
{
    return iter ? ((struct hashtable_pair *)((char *)iter - offsetof(struct hashtable_pair, list))) -> key : 0;
}

/* Retrieve the value from an iterator */
static inline void *hashtable_iter_value(void *iter)
{
    return iter ? ((struct hashtable_pair *)((char *)iter - offsetof(struct hashtable_pair, list))) -> value : 0;
}

/* Set the value at an iterator */
void hashtable_iter_set(hashtable_t *restrict hashtable, void *iter, void *restrict value);

#endif
