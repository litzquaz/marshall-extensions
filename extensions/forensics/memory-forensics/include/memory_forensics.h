/*
 * Memory Forensics Extension for Marshall Browser
 * Analyze in-memory artifacts and detect suspicious patterns
 * Written in C for low-level memory access
 * Part of Marshall Extensions Collection
 */

#ifndef MEMORY_FORENSICS_H
#define MEMORY_FORENSICS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version */
#define MF_VERSION_MAJOR 1
#define MF_VERSION_MINOR 0
#define MF_VERSION_PATCH 0

/* Memory artifact types */
typedef enum {
    MF_ARTIFACT_STRING,
    MF_ARTIFACT_URL,
    MF_ARTIFACT_EMAIL,
    MF_ARTIFACT_IP_ADDRESS,
    MF_ARTIFACT_CREDIT_CARD,
    MF_ARTIFACT_CRYPTO_KEY,
    MF_ARTIFACT_PASSWORD,
    MF_ARTIFACT_COOKIE,
    MF_ARTIFACT_TOKEN,
    MF_ARTIFACT_BASE64,
    MF_ARTIFACT_SHELLCODE,
    MF_ARTIFACT_PE_HEADER,
    MF_ARTIFACT_ELF_HEADER,
    MF_ARTIFACT_SCRIPT_TAG,
    MF_ARTIFACT_EVAL_CALL,
    MF_ARTIFACT_UNKNOWN
} mf_artifact_type_t;

/* Severity levels */
typedef enum {
    MF_SEVERITY_INFO = 0,
    MF_SEVERITY_LOW = 1,
    MF_SEVERITY_MEDIUM = 2,
    MF_SEVERITY_HIGH = 3,
    MF_SEVERITY_CRITICAL = 4
} mf_severity_t;

/* Memory region info */
typedef struct {
    uintptr_t base_address;
    size_t size;
    uint32_t permissions;  /* R=1, W=2, X=4 */
    char name[256];
    bool is_mapped;
    bool is_stack;
    bool is_heap;
} mf_memory_region_t;

/* Artifact structure */
typedef struct {
    mf_artifact_type_t type;
    mf_severity_t severity;
    uintptr_t address;
    size_t length;
    uint8_t* data;
    char description[512];
    uint64_t timestamp;
    uint32_t hash;
} mf_artifact_t;

/* Scan configuration */
typedef struct {
    bool scan_strings;
    bool scan_urls;
    bool scan_credentials;
    bool scan_shellcode;
    bool scan_headers;
    bool scan_scripts;
    size_t min_string_length;
    size_t max_string_length;
    bool include_unicode;
    uint32_t thread_count;
} mf_scan_config_t;

/* Scan results */
typedef struct {
    mf_artifact_t* artifacts;
    size_t artifact_count;
    size_t capacity;
    size_t bytes_scanned;
    uint64_t scan_duration_ms;
    uint32_t regions_scanned;
    bool complete;
} mf_scan_result_t;

/* Pattern for detection */
typedef struct {
    const char* name;
    const uint8_t* pattern;
    size_t pattern_length;
    const uint8_t* mask;  /* NULL for exact match */
    mf_artifact_type_t type;
    mf_severity_t severity;
} mf_pattern_t;

/* Callback for progress */
typedef void (*mf_progress_callback_t)(size_t bytes_scanned, size_t total_bytes, void* user_data);

/* Callback for artifact found */
typedef void (*mf_artifact_callback_t)(const mf_artifact_t* artifact, void* user_data);

/*
 * Initialize the forensics engine
 * Returns 0 on success, negative on error
 */
int mf_init(void);

/*
 * Cleanup and free resources
 */
void mf_cleanup(void);

/*
 * Get default scan configuration
 */
mf_scan_config_t mf_default_config(void);

/*
 * Enumerate memory regions
 * Returns number of regions found, or negative on error
 */
int mf_enumerate_regions(mf_memory_region_t** regions, size_t* count);

/*
 * Free enumerated regions
 */
void mf_free_regions(mf_memory_region_t* regions);

/*
 * Scan a memory buffer for artifacts
 */
mf_scan_result_t* mf_scan_buffer(
    const uint8_t* buffer,
    size_t length,
    const mf_scan_config_t* config,
    mf_progress_callback_t progress_cb,
    mf_artifact_callback_t artifact_cb,
    void* user_data
);

/*
 * Scan a specific memory region
 */
mf_scan_result_t* mf_scan_region(
    const mf_memory_region_t* region,
    const mf_scan_config_t* config,
    mf_artifact_callback_t artifact_cb,
    void* user_data
);

/*
 * Scan all accessible memory
 */
mf_scan_result_t* mf_scan_all(
    const mf_scan_config_t* config,
    mf_progress_callback_t progress_cb,
    mf_artifact_callback_t artifact_cb,
    void* user_data
);

/*
 * Free scan results
 */
void mf_free_result(mf_scan_result_t* result);

/*
 * Add custom detection pattern
 */
int mf_add_pattern(const mf_pattern_t* pattern);

/*
 * Remove custom pattern by name
 */
int mf_remove_pattern(const char* name);

/*
 * Search for specific byte pattern
 */
int mf_search_pattern(
    const uint8_t* buffer,
    size_t buffer_length,
    const uint8_t* pattern,
    size_t pattern_length,
    uintptr_t** matches,
    size_t* match_count
);

/*
 * Calculate entropy of memory region
 * High entropy may indicate encryption or compression
 */
double mf_calculate_entropy(const uint8_t* buffer, size_t length);

/*
 * Detect potential shellcode
 */
bool mf_detect_shellcode(const uint8_t* buffer, size_t length);

/*
 * Extract strings from memory
 */
int mf_extract_strings(
    const uint8_t* buffer,
    size_t length,
    size_t min_length,
    bool include_unicode,
    char*** strings,
    size_t* string_count
);

/*
 * Free extracted strings
 */
void mf_free_strings(char** strings, size_t count);

/*
 * Dump memory region to file
 */
int mf_dump_region(
    const mf_memory_region_t* region,
    const char* filepath
);

/*
 * Generate report in JSON format
 */
char* mf_generate_report(const mf_scan_result_t* result);

/*
 * Free generated report
 */
void mf_free_report(char* report);

/*
 * Get last error message
 */
const char* mf_get_error(void);

/*
 * Get version string
 */
const char* mf_get_version(void);

#ifdef __cplusplus
}
#endif

#endif /* MEMORY_FORENSICS_H */
