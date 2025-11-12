/*
 * profiling_runtime.c - Runtime library for dangerous API profiling
 * 
 * This library collects execution statistics for dangerous API calls
 * and writes them to a JSON file on program exit.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define MAX_ENTRIES 1024
#define MAX_NAME_LEN 256

// Structure to hold profiling data for each API-caller pair
typedef struct {
    char api_name[MAX_NAME_LEN];
    char caller_name[MAX_NAME_LEN];
    unsigned long count;
    struct timespec first_call;
    struct timespec last_call;
} ProfileEntry;

// Global data structure
static ProfileEntry profile_data[MAX_ENTRIES];
static int num_entries = 0;
static pthread_mutex_t profile_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialized = 0;

// Function to find or create an entry
static int find_or_create_entry(const char* api_name, const char* caller_name) {
    // Search for existing entry
    for (int i = 0; i < num_entries; i++) {
        if (strcmp(profile_data[i].api_name, api_name) == 0 &&
            strcmp(profile_data[i].caller_name, caller_name) == 0) {
            return i;
        }
    }
    
    // Creates new entry if space available
    if (num_entries < MAX_ENTRIES) {
        int idx = num_entries++;
        strncpy(profile_data[idx].api_name, api_name, MAX_NAME_LEN - 1);
        strncpy(profile_data[idx].caller_name, caller_name, MAX_NAME_LEN - 1);
        profile_data[idx].count = 0;
        clock_gettime(CLOCK_MONOTONIC, &profile_data[idx].first_call);
        return idx;
    }
    
    return -1; // No space
}

// Main profiling function called by instrumented code
void profiling_log(const char* api_name, const char* caller_name) {
    pthread_mutex_lock(&profile_mutex);
    
    int idx = find_or_create_entry(api_name, caller_name);
    if (idx >= 0) {
        profile_data[idx].count++;
        clock_gettime(CLOCK_MONOTONIC, &profile_data[idx].last_call);
    }
    
    pthread_mutex_unlock(&profile_mutex);
}

// Calculates time difference in milliseconds
static double time_diff_ms(struct timespec *start, struct timespec *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 + 
           (end->tv_nsec - start->tv_nsec) / 1000000.0;
}

// Writes profiling data to JSON file on exit
static void write_profile_data(void) {
    FILE *fp = fopen("dangerous_api_profile.json", "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open output file\n");
        return;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"profile_data\": [\n");
    
    unsigned long total_calls = 0;
    for (int i = 0; i < num_entries; i++) {
        total_calls += profile_data[i].count;
    }
    
    for (int i = 0; i < num_entries; i++) {
        double duration = time_diff_ms(&profile_data[i].first_call, 
                                       &profile_data[i].last_call);
        double percentage = total_calls > 0 ? 
                           (profile_data[i].count * 100.0 / total_calls) : 0.0;
        
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"api_name\": \"%s\",\n", profile_data[i].api_name);
        fprintf(fp, "      \"caller_function\": \"%s\",\n", profile_data[i].caller_name);
        fprintf(fp, "      \"execution_count\": %lu,\n", profile_data[i].count);
        fprintf(fp, "      \"percentage_of_total\": %.2f,\n", percentage);
        fprintf(fp, "      \"duration_ms\": %.3f\n", duration);
        fprintf(fp, "    }%s\n", (i < num_entries - 1) ? "," : "");
    }
    
    fprintf(fp, "  ],\n");
    fprintf(fp, "  \"summary\": {\n");
    fprintf(fp, "    \"total_dangerous_calls\": %lu,\n", total_calls);
    fprintf(fp, "    \"unique_call_sites\": %d\n", num_entries);
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
    
    // Also print summary to console
    printf("\n=== Dangerous API Profiling Results ===\n");
    printf("Total dangerous API calls: %lu\n", total_calls);
    printf("Unique call sites: %d\n", num_entries);
    printf("Results written to: dangerous_api_profile.json\n\n");
    
    printf("Top call sites:\n");
    for (int i = 0; i < num_entries && i < 10; i++) {
        printf("  %s() -> %s: %lu calls (%.1f%%)\n", 
               profile_data[i].caller_name,
               profile_data[i].api_name,
               profile_data[i].count,
               (profile_data[i].count * 100.0 / total_calls));
    }
}

// Constructor to register exit handler
__attribute__((constructor))
static void profiling_init(void) {
    if (!initialized) {
        atexit(write_profile_data);
        initialized = 1;
    }
}