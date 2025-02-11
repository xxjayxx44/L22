/*
 * miner_optimized.c
 *
 * This file implements a multi-threaded miner using random nonce selection
 * and the Yespower "Urx" hashing algorithm.
 *
 * IMPORTANT:
 *   - Compile ONLY this file along with YespowerUrx.c.
 *   - Do NOT include cpu-miner.c or any other file that defines main().
 *
 * Example compile command on Ubuntu:
 *     gcc -O2 -pthread miner_optimized.c YespowerUrx.c -o miner -lcrypto -lcurl
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>   // for sysconf()

// Include your Yespower header (adjust the filename if necessary)
#include "yespower.h"  // Ensure this declares scanhash_urx_yespower (or similar)

//---------------------------------------------------------------------
// Wrapper: Map yespower_hash() to the actual function implementation.
// If your Yespower implementation is defined as scanhash_urx_yespower,
// uncomment and use the wrapper below.

extern int scanhash_urx_yespower(const void *input, size_t inputlen, void *output);
int yespower_hash(const void *input, size_t inputlen, void *output) {
    return scanhash_urx_yespower(input, inputlen, output);
}

//---------------------------------------------------------------------
// Global parameters and shared data

// Define your target difficulty (example value).
#define DIFFICULTY_TARGET 0x00000fffffffffffffULL

// Global flag to signal when a valid hash is found.
volatile int found = 0;
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;

// Structure to store the successful nonce and hash.
typedef struct {
    uint32_t nonce;
    uint8_t hash[32];
} result_t;

result_t result;

//---------------------------------------------------------------------
// Helper function: Convert the first 8 bytes of hash into a uint64_t.
// (Assumes little-endian; adjust if necessary.)
static inline uint64_t convert_hash_to_uint64(const uint8_t *hash) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t) hash[i]) << (8 * i);
    }
    return value;
}

// Check if a hash meets the difficulty target.
int is_valid_hash(const uint8_t *hash) {
    uint64_t hash_val = convert_hash_to_uint64(hash);
    return (hash_val < DIFFICULTY_TARGET);
}

//---------------------------------------------------------------------
// Worker thread function
void *mine_thread(void *arg) {
    // Each thread uses its own seed for rand_r.
    unsigned int seed = (unsigned int) time(NULL) ^ (unsigned int)(uintptr_t)pthread_self();

    // Define the input buffer. For example, assume an 80-byte block header.
    uint8_t input[80];
    memset(input, 0, sizeof(input));

    // Define where in the input the nonce should be inserted.
    // (Adjust this offset to match your protocol.)
    const size_t nonce_offset = 72;

    // Buffer to hold the resulting 32-byte hash.
    uint8_t hash[32];

    // Mining loop: try random nonces until a valid hash is found.
    while (!found) {
        // Generate a random 32-bit nonce using the thread-safe rand_r.
        uint32_t nonce = (uint32_t) rand_r(&seed);

        // Insert the nonce into the input buffer.
        memcpy(input + nonce_offset, &nonce, sizeof(nonce));

        // Compute the hash using the Yespower algorithm.
        if (yespower_hash(input, sizeof(input), hash) != 0) {
            // If an error occurs in hash computation, skip this nonce.
            continue;
        }

        // Check if the computed hash meets the difficulty target.
        if (is_valid_hash(hash)) {
            pthread_mutex_lock(&found_mutex);
            if (!found) {  // Double-check inside the critical section.
                found = 1;
                result.nonce = nonce;
                memcpy(result.hash, hash, sizeof(result.hash));
            }
            pthread_mutex_unlock(&found_mutex);
            break;
        }
    }
    return NULL;
}

//---------------------------------------------------------------------
// Main function
int main(int argc, char **argv) {
    // Determine the number of threads to use.
    int num_threads = 4; // Default.
    long cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores > 0) {
        num_threads = (int) cores;
    }
    printf("Starting mining with %d thread(s)...\n", num_threads);

    // Allocate thread handles.
    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    if (!threads) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    // Create worker threads.
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, mine_thread, NULL) != 0) {
            perror("pthread_create");
            free(threads);
            return EXIT_FAILURE;
        }
    }

    // Wait for all threads to finish.
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    free(threads);

    // If a valid hash was found, print the result.
    if (found) {
        printf("Valid hash found!\nNonce: %u\nHash: ", result.nonce);
        for (int i = 0; i < 32; i++) {
            printf("%02x", result.hash[i]);
        }
        printf("\n");
    } else {
        printf("No valid hash found.\n");
    }
    return EXIT_SUCCESS;
}
