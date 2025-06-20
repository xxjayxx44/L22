/*
 * Modernized open-addressing hash table
 * Optimized for high-throughput insert/lookup/deletion
 * particularly suited for yespowerurx hash caching
 *
 * Copyright (c) 2009-2025, Modernized
 * Released under MIT License
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>

// FNV-1a 64-bit hash for byte buffer
static inline uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *p = data;
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// Hashtable entry states
typedef enum { EMPTY, OCCUPIED, DELETED } ht_state_t;

typedef struct {
    void *key;
    void *value;
    uint64_t hash;
    ht_state_t state;
} ht_entry_t;

typedef struct {
    ht_entry_t *entries;
    size_t capacity;
    size_t mask;
    size_t size;
    size_t tombstones;
    float max_load; // e.g., 0.7
    // user callbacks
    void (*free_key)(void *);
    void (*free_value)(void *);
    uint64_t (*hash_fn)(const void *);
    bool (*key_eq)(const void *, const void *);
} hashtable_t;

// Round up to next power of two
static inline size_t next_pow2(size_t x) {
    if (x <= 1) return 1;
    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    if (sizeof(size_t) > 4)
        x |= x >> 32;
    return x + 1;
}

static void ht_resize(hashtable_t *ht, size_t new_capacity) {
    ht_entry_t *old = ht->entries;
    size_t old_cap = ht->capacity;

    ht->capacity = new_capacity;
    ht->mask = new_capacity - 1;
    ht->entries = calloc(new_capacity, sizeof(ht_entry_t));
    assert(ht->entries);
    ht->size = 0;
    ht->tombstones = 0;

    for (size_t i = 0; i < old_cap; i++) {
        if (old[i].state == OCCUPIED) {
            void *k = old[i].key;
            void *v = old[i].value;
            uint64_t h = old[i].hash;
            size_t idx = h & ht->mask;
            while (ht->entries[idx].state == OCCUPIED) {
                idx = (idx + 1) & ht->mask;
            }
            ht->entries[idx].key = k;
            ht->entries[idx].value = v;
            ht->entries[idx].hash = h;
            ht->entries[idx].state = OCCUPIED;
            ht->size++;
        }
    }
    free(old);
}

hashtable_t *ht_create(size_t initial_capacity,
                       float max_load,
                       uint64_t (*hash_fn)(const void *),
                       bool (*key_eq)(const void *, const void *),
                       void (*free_key)(void *),
                       void (*free_value)(void *)) {
    hashtable_t *ht = malloc(sizeof(*ht));
    assert(ht);
    size_t cap = next_pow2(initial_capacity);
    ht->capacity = cap;
    ht->mask = cap - 1;
    ht->size = 0;
    ht->tombstones = 0;
    ht->max_load = max_load;
    ht->hash_fn = hash_fn ? hash_fn : fnv1a64;
    ht->key_eq = key_eq;
    ht->free_key = free_key;
    ht->free_value = free_value;
    ht->entries = calloc(cap, sizeof(ht_entry_t));
    assert(ht->entries);
    return ht;
}

void ht_destroy(hashtable_t *ht) {
    for (size_t i = 0; i < ht->capacity; i++) {
        if (ht->entries[i].state == OCCUPIED) {
            if (ht->free_key) ht->free_key(ht->entries[i].key);
            if (ht->free_value) ht->free_value(ht->entries[i].value);
        }
    }
    free(ht->entries);
    free(ht);
}

bool ht_set(hashtable_t *ht, void *key, void *value) {
    if ((ht->size + ht->tombstones + 1) > (size_t)(ht->capacity * ht->max_load)) {
        ht_resize(ht, ht->capacity * 2);
    }
    uint64_t h = ht->hash_fn(key);
    size_t idx = h & ht->mask;
    ssize_t first_tomb = -1;
    while (true) {
        ht_entry_t *e = &ht->entries[idx];
        if (e->state == EMPTY) {
            size_t target = (first_tomb >= 0) ? (size_t)first_tomb : idx;
            ht_entry_t *ne = &ht->entries[target];
            ne->key = key;
            ne->value = value;
            ne->hash = h;
            ne->state = OCCUPIED;
            ht->size++;
            if (first_tomb >= 0) ht->tombstones--;
            return true;
        } else if (e->state == DELETED) {
            if (first_tomb < 0) first_tomb = idx;
        } else if (e->hash == h && ht->key_eq(e->key, key)) {
            if (ht->free_key) ht->free_key(e->key);
            if (ht->free_value) ht->free_value(e->value);
            e->key = key;
            e->value = value;
            return true;
        }
        idx = (idx + 1) & ht->mask;
    }
}

void *ht_get(const hashtable_t *ht, const void *key) {
    uint64_t h = ht->hash_fn(key);
    size_t idx = h & ht->mask;
    while (true) {
        const ht_entry_t *e = &ht->entries[idx];
        if (e->state == EMPTY) return NULL;
        if (e->state == OCCUPIED && e->hash == h && ht->key_eq(e->key, key)) {
            return e->value;
        }
        idx = (idx + 1) & ht->mask;
    }
}

bool ht_del(hashtable_t *ht, const void *key) {
    uint64_t h = ht->hash_fn(key);
    size_t idx = h & ht->mask;
    while (true) {
        ht_entry_t *e = &ht->entries[idx];
        if (e->state == EMPTY) return false;
        if (e->state == OCCUPIED && e->hash == h && ht->key_eq(e->key, key)) {
            e->state = DELETED;
            if (ht->free_key) ht->free_key(e->key);
            if (ht->free_value) ht->free_value(e->value);
            ht->size--;
            ht->tombstones++;
            return true;
        }
        idx = (idx + 1) & ht->mask;
    }
}

size_t ht_size(const hashtable_t *ht) {
    return ht->size;
}

void ht_clear(hashtable_t *ht) {
    for (size_t i = 0; i < ht->capacity; i++) {
        if (ht->entries[i].state == OCCUPIED) {
            if (ht->free_key) ht->free_key(ht->entries[i].key);
            if (ht->free_value) ht->free_value(ht->entries[i].value);
        }
        ht->entries[i].state = EMPTY;
    }
    ht->size = 0;
    ht->tombstones = 0;
}
