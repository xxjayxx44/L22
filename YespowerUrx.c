/*
 * miner.c
 *
 * This file implements a simple miner that uses the Yespower "Urx" hashing
 * algorithm to solve a proof-of-work puzzle by randomizing the nonce.
 *
 * The miner uses an 80-byte input (e.g. a block header) and inserts a
 * random 32-bit nonce at a specified offset. The resulting hash is computed
 * using Yespower (provided by YespowerUrx.c) and compared against a target
 * difficulty.
 *
 * The target difficulty can be adjusted to match the pool you'll connect to.
 * You can provide the target difficulty as a command-line argument, either
 * in hexadecimal (prefix with "0x") or as a decimal number.
 *
 * Compile on Ubuntu with:
 *     gcc -O2 miner.c YespowerUrx.c -o miner
 *
 * Usage:
 *     ./miner [difficulty_target]
 *   - If no target is provided, a default is used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>


// Default target difficulty (example value)
#define DEFAULT_DIFFICULTY_TARGET 0x00000fffffffffffffULL

// Helper function: Convert the first 8 bytes of the hash into a uint64_t value.
// This function assumes the hash is in little-endian order.
static inline uint64_t convert_hash_to_uint64(const uint8_t *hash) {
    uint64_t value = 0;
    for (int i = 0; i < 8; i++) {
        value |= ((uint64_t)hash[i]) << (8 * i);
    }
    return value;
}

// Checks if the computed hash meets the target difficulty.
// A valid hash is one whose (numerical) value is less than the target.
int is_valid_hash(const uint8_t *hash, uint64_t target) {
    uint64_t hash_val = convert_hash_to_uint64(hash);
    return (hash_val < target);
}

int main(int argc, char *argv[]) {
    // Determine the difficulty target.
    // If a command-line parameter is provided, parse it.
    // The parameter can be in hexadecimal (if it starts with "0x") or decimal.
    uint64_t difficulty_target = DEFAULT_DIFFICULTY_TARGET;
    if (argc > 1) {
        if (strncmp(argv[1], "0x", 2) == 0) {
            difficulty_target = strtoull(argv[1], NULL, 16);
        } else {
            difficulty_target = strtoull(argv[1], NULL, 10);
        }
        printf("Using provided difficulty target: 0x%016llx\n", (unsigned long long)difficulty_target);
    } else {
        printf("Using default difficulty target: 0x%016llx\n", (unsigned long long)difficulty_target);
    }

    // Prepare the input buffer.
    // For example, this might be an 80-byte block header.
    uint8_t input[80];
    memset(input, 0, sizeof(input));

    // Define the offset in the input buffer where the nonce will be inserted.
    // Adjust this offset according to your protocol's specification.
    const size_t nonce_offset = 72;  // (Example: nonce inserted at offset 72)

    // Buffer to store the resulting 32-byte hash.
    uint8_t hash[32];

    // Seed the random number generator.
    srand((unsigned)time(NULL));

    // Mining loop: continuously try random nonces until a valid hash is found.
    for (;;) {
        // Generate a random 32-bit nonce.
        uint32_t nonce = (uint32_t)rand();

        // Insert the nonce into the input buffer at the specified offset.
        memcpy(input + nonce_offset, &nonce, sizeof(nonce));

        // Compute the Yespower hash.
        // The function yespower_hash is expected to be defined in YespowerUrx.c.
        if (yespower_hash(input, sizeof(input), hash) != 0) {
            fprintf(stderr, "Error computing Yespower hash.\n");
            continue;
        }

        // Validate the computed hash against the current target difficulty.
        if (is_valid_hash(hash, difficulty_target)) {
            printf("Valid hash found!\nNonce: %u\nHash: ", nonce);
            for (int i = 0; i < 32; i++) {
                printf("%02x", hash[i]);
            }
            printf("\n");
            break;
        }
    }

    return 0;
}
