/*
 * mining_optimized.c
 *
 * This file implements a multi-threaded miner that uses randomization
 * for nonce selection and the Yespower "Urx" hashing algorithm.
 *
 * Compile on Ubuntu with:
 *     gcc -O2 -pthread mining_optimized.c YespowerUrx.c -o miner
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>     // For sysconf()

// Include your Yespower header (adjust the filename if necessary)
#include "yespower.h"   // or #include "YespowerUrx.h"

//---------------------------------------------------------------------
// Global parameters and shared data

// Define your target difficulty (example value).
#define DIFFICULTY_TARGET 0x00000fffffffffffffULL

// Global flag to signal when a valid hash is found.
volatile int found = 0;
// Mutex to protect access to the shared result.
pthread_mutex_t found_mutex = PTHREAD_MUTEX_INITIALIZER;

// Structure to store the successful nonce and hash.
typedef struct {
    uint32_t nonce;
    uint8_t hash[32];
} result_t;

result_t result;

//---------------------------------------------------------------------
// Helper function: convert the first 8 bytes of hash into a uint64_t.
// Adjust this conversion if your chain uses a different endianness.
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

    // Define the input buffer. In this example, assume an 80-byte block header.
    uint8_t input[80];
    memset(input, 0, sizeof(input));

    // Define where in the input the nonce should be inserted.
    // (Adjust this offset to match your protocol specifications.)
    const size_t nonce_offset = 72;

    // Buffer to hold the resulting 32-byte hash.
    uint8_t hash[32];

    // Mining loop: try random nonces until a valid hash is found.
    while (!found) {
        // Generate a random 32-bit nonce using the thread-safe rand_r.
        uint32_t nonce = (uint32_t) rand_r(&seed);

        // Insert the nonce into the input buffer (assuming little-endian format).
        memcpy(input + nonce_offset, &nonce, sizeof(nonce));

        // Compute the hash using the Yespower algorithm.
        if (yespower_hash(input, sizeof(input), hash) != 0) {
            // If an error occurs in hash computation, skip this nonce.
            continue;
        }

        // Check whether the computed hash meets the difficulty target.
        if (is_valid_hash(hash)) {
            // Lock the mutex to update the shared result.
            pthread_mutex_lock(&found_mutex);
            if (!found) {
                found = 1;  // Signal that a valid hash has been found.
                result.nonce = nonce;
                memcpy(result.hash, hash, sizeof(result.hash));
            }
            pthread_mutex_unlock(&found_mutex);
            break;  // Exit the loop as we have found a valid hash.
        }
    }
    return NULL;
}

//---------------------------------------------------------------------
// Main function: sets up and starts the mining threads.
int main(int argc, char **argv) {
    // Determine the number of threads to use.
    // Use the number of available processor cores if possible.
    int num_threads = 4; // Default value.
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

    // Create the worker threads.
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

    // If a valid hash was found, print the results.
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
