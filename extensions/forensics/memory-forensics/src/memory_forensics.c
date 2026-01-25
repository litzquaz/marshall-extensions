/*
 * Memory Forensics Engine Implementation
 * Part of Marshall Extensions Collection
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <math.h>

#ifdef __linux__
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "memory_forensics.h"

/* Internal state */
static bool g_initialized = false;
static char g_error_message[512] = {0};
static mf_pattern_t* g_custom_patterns = NULL;
static size_t g_pattern_count = 0;

/* Built-in detection patterns */
static const uint8_t PATTERN_SHELLCODE_NOP[] = {0x90, 0x90, 0x90, 0x90, 0x90};
static const uint8_t PATTERN_PE_HEADER[] = {0x4D, 0x5A};  /* MZ */
static const uint8_t PATTERN_ELF_HEADER[] = {0x7F, 0x45, 0x4C, 0x46};  /* ELF */
static const uint8_t PATTERN_SCRIPT_TAG[] = "<script";
static const uint8_t PATTERN_EVAL[] = "eval(";

/* Common credit card prefixes (for detection, not validation) */
static const char* CREDIT_CARD_PREFIXES[] = {"4", "51", "52", "53", "54", "55", "34", "37"};

/* URL regex approximation */
static const char* URL_PATTERNS[] = {"http://", "https://", "ftp://", "file://", "data:"};

/* Helper: Set error message */
static void set_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_error_message, sizeof(g_error_message), fmt, args);
    va_end(args);
}

/* Helper: Calculate hash */
static uint32_t calc_hash(const uint8_t* data, size_t length) {
    uint32_t hash = 5381;
    for (size_t i = 0; i < length; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}

/* Helper: Check if printable ASCII string */
static bool is_printable_string(const uint8_t* data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (data[i] < 0x20 || data[i] > 0x7E) {
            if (data[i] != '\t' && data[i] != '\n' && data[i] != '\r') {
                return false;
            }
        }
    }
    return true;
}

/* Helper: Check if valid email pattern */
static bool is_email_pattern(const char* str, size_t length) {
    const char* at = memchr(str, '@', length);
    if (!at) return false;
    
    const char* dot = memchr(at, '.', length - (at - str));
    if (!dot) return false;
    
    return (at - str) > 0 && (dot - at) > 1 && (length - (dot - str)) > 2;
}

/* Helper: Check if potential credit card number */
static bool is_credit_card_pattern(const char* str, size_t length) {
    if (length < 13 || length > 19) return false;
    
    int digit_count = 0;
    for (size_t i = 0; i < length; i++) {
        if (isdigit(str[i])) {
            digit_count++;
        } else if (str[i] != '-' && str[i] != ' ') {
            return false;
        }
    }
    
    return digit_count >= 13 && digit_count <= 19;
}

/* Helper: Luhn algorithm for credit card validation */
static bool luhn_check(const char* number, size_t length) {
    int sum = 0;
    bool alternate = false;
    
    for (int i = length - 1; i >= 0; i--) {
        if (!isdigit(number[i])) continue;
        
        int digit = number[i] - '0';
        if (alternate) {
            digit *= 2;
            if (digit > 9) digit -= 9;
        }
        sum += digit;
        alternate = !alternate;
    }
    
    return (sum % 10) == 0;
}

/* Initialize engine */
int mf_init(void) {
    if (g_initialized) {
        return 0;
    }
    
    g_custom_patterns = NULL;
    g_pattern_count = 0;
    g_error_message[0] = '\0';
    g_initialized = true;
    
    return 0;
}

/* Cleanup */
void mf_cleanup(void) {
    if (g_custom_patterns) {
        free(g_custom_patterns);
        g_custom_patterns = NULL;
    }
    g_pattern_count = 0;
    g_initialized = false;
}

/* Get default config */
mf_scan_config_t mf_default_config(void) {
    mf_scan_config_t config = {
        .scan_strings = true,
        .scan_urls = true,
        .scan_credentials = true,
        .scan_shellcode = true,
        .scan_headers = true,
        .scan_scripts = true,
        .min_string_length = 4,
        .max_string_length = 1024,
        .include_unicode = true,
        .thread_count = 4
    };
    return config;
}

/* Calculate entropy */
double mf_calculate_entropy(const uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return 0.0;
    
    size_t frequency[256] = {0};
    
    for (size_t i = 0; i < length; i++) {
        frequency[buffer[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / length;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

/* Detect shellcode */
bool mf_detect_shellcode(const uint8_t* buffer, size_t length) {
    if (!buffer || length < 10) return false;
    
    /* Check for NOP sled */
    int nop_count = 0;
    for (size_t i = 0; i < length; i++) {
        if (buffer[i] == 0x90) {
            nop_count++;
            if (nop_count >= 10) return true;
        } else {
            nop_count = 0;
        }
    }
    
    /* Check entropy - shellcode often has high entropy */
    double entropy = mf_calculate_entropy(buffer, length);
    if (entropy > 6.5 && entropy < 7.5) {
        /* Suspicious entropy range */
        return true;
    }
    
    /* Check for common shellcode instructions */
    /* INT 0x80 (Linux syscall) */
    for (size_t i = 0; i < length - 1; i++) {
        if (buffer[i] == 0xCD && buffer[i+1] == 0x80) {
            return true;
        }
    }
    
    /* SYSCALL instruction (x64) */
    for (size_t i = 0; i < length - 1; i++) {
        if (buffer[i] == 0x0F && buffer[i+1] == 0x05) {
            return true;
        }
    }
    
    return false;
}

/* Search for byte pattern */
int mf_search_pattern(
    const uint8_t* buffer,
    size_t buffer_length,
    const uint8_t* pattern,
    size_t pattern_length,
    uintptr_t** matches,
    size_t* match_count
) {
    if (!buffer || !pattern || !matches || !match_count) {
        set_error("Invalid parameters");
        return -1;
    }
    
    *matches = NULL;
    *match_count = 0;
    
    size_t capacity = 64;
    *matches = malloc(capacity * sizeof(uintptr_t));
    if (!*matches) {
        set_error("Memory allocation failed");
        return -1;
    }
    
    for (size_t i = 0; i <= buffer_length - pattern_length; i++) {
        if (memcmp(buffer + i, pattern, pattern_length) == 0) {
            if (*match_count >= capacity) {
                capacity *= 2;
                uintptr_t* new_matches = realloc(*matches, capacity * sizeof(uintptr_t));
                if (!new_matches) {
                    free(*matches);
                    *matches = NULL;
                    return -1;
                }
                *matches = new_matches;
            }
            (*matches)[(*match_count)++] = i;
        }
    }
    
    return 0;
}

/* Extract strings */
int mf_extract_strings(
    const uint8_t* buffer,
    size_t length,
    size_t min_length,
    bool include_unicode,
    char*** strings,
    size_t* string_count
) {
    if (!buffer || !strings || !string_count) {
        set_error("Invalid parameters");
        return -1;
    }
    
    *strings = NULL;
    *string_count = 0;
    
    size_t capacity = 256;
    *strings = malloc(capacity * sizeof(char*));
    if (!*strings) {
        set_error("Memory allocation failed");
        return -1;
    }
    
    size_t start = 0;
    bool in_string = false;
    
    for (size_t i = 0; i < length; i++) {
        bool is_printable = (buffer[i] >= 0x20 && buffer[i] <= 0x7E) ||
                           buffer[i] == '\t' || buffer[i] == '\n' || buffer[i] == '\r';
        
        if (is_printable && !in_string) {
            start = i;
            in_string = true;
        } else if (!is_printable && in_string) {
            size_t str_len = i - start;
            if (str_len >= min_length) {
                if (*string_count >= capacity) {
                    capacity *= 2;
                    char** new_strings = realloc(*strings, capacity * sizeof(char*));
                    if (!new_strings) {
                        mf_free_strings(*strings, *string_count);
                        return -1;
                    }
                    *strings = new_strings;
                }
                
                (*strings)[*string_count] = malloc(str_len + 1);
                if ((*strings)[*string_count]) {
                    memcpy((*strings)[*string_count], buffer + start, str_len);
                    (*strings)[*string_count][str_len] = '\0';
                    (*string_count)++;
                }
            }
            in_string = false;
        }
    }
    
    return 0;
}

/* Free strings */
void mf_free_strings(char** strings, size_t count) {
    if (strings) {
        for (size_t i = 0; i < count; i++) {
            free(strings[i]);
        }
        free(strings);
    }
}

/* Scan buffer */
mf_scan_result_t* mf_scan_buffer(
    const uint8_t* buffer,
    size_t length,
    const mf_scan_config_t* config,
    mf_progress_callback_t progress_cb,
    mf_artifact_callback_t artifact_cb,
    void* user_data
) {
    if (!buffer || !config) {
        set_error("Invalid parameters");
        return NULL;
    }
    
    mf_scan_result_t* result = calloc(1, sizeof(mf_scan_result_t));
    if (!result) {
        set_error("Memory allocation failed");
        return NULL;
    }
    
    result->capacity = 256;
    result->artifacts = calloc(result->capacity, sizeof(mf_artifact_t));
    if (!result->artifacts) {
        free(result);
        return NULL;
    }
    
    clock_t start_time = clock();
    
    /* Extract and analyze strings */
    if (config->scan_strings) {
        char** strings = NULL;
        size_t string_count = 0;
        
        if (mf_extract_strings(buffer, length, config->min_string_length,
                               config->include_unicode, &strings, &string_count) == 0) {
            
            for (size_t i = 0; i < string_count; i++) {
                const char* str = strings[i];
                size_t str_len = strlen(str);
                
                mf_artifact_t artifact = {0};
                artifact.timestamp = time(NULL);
                artifact.length = str_len;
                artifact.data = (uint8_t*)strdup(str);
                
                /* Check for URLs */
                if (config->scan_urls) {
                    for (int j = 0; j < sizeof(URL_PATTERNS)/sizeof(URL_PATTERNS[0]); j++) {
                        if (strstr(str, URL_PATTERNS[j])) {
                            artifact.type = MF_ARTIFACT_URL;
                            artifact.severity = MF_SEVERITY_INFO;
                            snprintf(artifact.description, sizeof(artifact.description),
                                    "URL found: %.100s", str);
                            break;
                        }
                    }
                }
                
                /* Check for emails */
                if (artifact.type == 0 && is_email_pattern(str, str_len)) {
                    artifact.type = MF_ARTIFACT_EMAIL;
                    artifact.severity = MF_SEVERITY_LOW;
                    snprintf(artifact.description, sizeof(artifact.description),
                            "Email address found");
                }
                
                /* Check for credit cards */
                if (artifact.type == 0 && config->scan_credentials &&
                    is_credit_card_pattern(str, str_len)) {
                    if (luhn_check(str, str_len)) {
                        artifact.type = MF_ARTIFACT_CREDIT_CARD;
                        artifact.severity = MF_SEVERITY_CRITICAL;
                        snprintf(artifact.description, sizeof(artifact.description),
                                "Valid credit card number detected!");
                    }
                }
                
                /* Check for script tags */
                if (config->scan_scripts && strstr(str, "<script")) {
                    artifact.type = MF_ARTIFACT_SCRIPT_TAG;
                    artifact.severity = MF_SEVERITY_MEDIUM;
                    snprintf(artifact.description, sizeof(artifact.description),
                            "Script tag found in memory");
                }
                
                /* Check for eval() */
                if (config->scan_scripts && strstr(str, "eval(")) {
                    artifact.type = MF_ARTIFACT_EVAL_CALL;
                    artifact.severity = MF_SEVERITY_HIGH;
                    snprintf(artifact.description, sizeof(artifact.description),
                            "eval() call detected - potential code injection");
                }
                
                /* Add artifact if type was set */
                if (artifact.type != 0) {
                    artifact.hash = calc_hash(artifact.data, artifact.length);
                    
                    if (result->artifact_count >= result->capacity) {
                        result->capacity *= 2;
                        result->artifacts = realloc(result->artifacts,
                                                   result->capacity * sizeof(mf_artifact_t));
                    }
                    
                    result->artifacts[result->artifact_count++] = artifact;
                    
                    if (artifact_cb) {
                        artifact_cb(&artifact, user_data);
                    }
                } else {
                    free(artifact.data);
                }
            }
            
            mf_free_strings(strings, string_count);
        }
    }
    
    /* Check for shellcode */
    if (config->scan_shellcode && mf_detect_shellcode(buffer, length)) {
        mf_artifact_t artifact = {
            .type = MF_ARTIFACT_SHELLCODE,
            .severity = MF_SEVERITY_CRITICAL,
            .length = length < 256 ? length : 256,
            .timestamp = time(NULL)
        };
        artifact.data = malloc(artifact.length);
        if (artifact.data) {
            memcpy(artifact.data, buffer, artifact.length);
            snprintf(artifact.description, sizeof(artifact.description),
                    "Potential shellcode detected! Entropy: %.2f",
                    mf_calculate_entropy(buffer, length));
            artifact.hash = calc_hash(artifact.data, artifact.length);
            
            result->artifacts[result->artifact_count++] = artifact;
            
            if (artifact_cb) {
                artifact_cb(&artifact, user_data);
            }
        }
    }
    
    /* Check for PE/ELF headers */
    if (config->scan_headers) {
        /* PE header */
        uintptr_t* pe_matches = NULL;
        size_t pe_count = 0;
        if (mf_search_pattern(buffer, length, PATTERN_PE_HEADER, 2, &pe_matches, &pe_count) == 0) {
            for (size_t i = 0; i < pe_count; i++) {
                mf_artifact_t artifact = {
                    .type = MF_ARTIFACT_PE_HEADER,
                    .severity = MF_SEVERITY_HIGH,
                    .address = pe_matches[i],
                    .length = 64,
                    .timestamp = time(NULL)
                };
                snprintf(artifact.description, sizeof(artifact.description),
                        "PE header found at offset 0x%lx", pe_matches[i]);
                
                result->artifacts[result->artifact_count++] = artifact;
            }
            free(pe_matches);
        }
        
        /* ELF header */
        uintptr_t* elf_matches = NULL;
        size_t elf_count = 0;
        if (mf_search_pattern(buffer, length, PATTERN_ELF_HEADER, 4, &elf_matches, &elf_count) == 0) {
            for (size_t i = 0; i < elf_count; i++) {
                mf_artifact_t artifact = {
                    .type = MF_ARTIFACT_ELF_HEADER,
                    .severity = MF_SEVERITY_HIGH,
                    .address = elf_matches[i],
                    .length = 64,
                    .timestamp = time(NULL)
                };
                snprintf(artifact.description, sizeof(artifact.description),
                        "ELF header found at offset 0x%lx", elf_matches[i]);
                
                result->artifacts[result->artifact_count++] = artifact;
            }
            free(elf_matches);
        }
    }
    
    result->bytes_scanned = length;
    result->scan_duration_ms = (clock() - start_time) * 1000 / CLOCKS_PER_SEC;
    result->complete = true;
    
    if (progress_cb) {
        progress_cb(length, length, user_data);
    }
    
    return result;
}

/* Free result */
void mf_free_result(mf_scan_result_t* result) {
    if (result) {
        if (result->artifacts) {
            for (size_t i = 0; i < result->artifact_count; i++) {
                free(result->artifacts[i].data);
            }
            free(result->artifacts);
        }
        free(result);
    }
}

/* Generate JSON report */
char* mf_generate_report(const mf_scan_result_t* result) {
    if (!result) return NULL;
    
    size_t buffer_size = 4096 + result->artifact_count * 1024;
    char* report = malloc(buffer_size);
    if (!report) return NULL;
    
    char* ptr = report;
    ptr += sprintf(ptr, "{\n");
    ptr += sprintf(ptr, "  \"scan_complete\": %s,\n", result->complete ? "true" : "false");
    ptr += sprintf(ptr, "  \"bytes_scanned\": %zu,\n", result->bytes_scanned);
    ptr += sprintf(ptr, "  \"duration_ms\": %lu,\n", result->scan_duration_ms);
    ptr += sprintf(ptr, "  \"artifact_count\": %zu,\n", result->artifact_count);
    ptr += sprintf(ptr, "  \"artifacts\": [\n");
    
    for (size_t i = 0; i < result->artifact_count; i++) {
        const mf_artifact_t* a = &result->artifacts[i];
        ptr += sprintf(ptr, "    {\n");
        ptr += sprintf(ptr, "      \"type\": %d,\n", a->type);
        ptr += sprintf(ptr, "      \"severity\": %d,\n", a->severity);
        ptr += sprintf(ptr, "      \"address\": \"0x%lx\",\n", a->address);
        ptr += sprintf(ptr, "      \"length\": %zu,\n", a->length);
        ptr += sprintf(ptr, "      \"hash\": \"0x%08x\",\n", a->hash);
        ptr += sprintf(ptr, "      \"description\": \"%s\"\n", a->description);
        ptr += sprintf(ptr, "    }%s\n", (i < result->artifact_count - 1) ? "," : "");
    }
    
    ptr += sprintf(ptr, "  ]\n");
    ptr += sprintf(ptr, "}\n");
    
    return report;
}

/* Free report */
void mf_free_report(char* report) {
    free(report);
}

/* Get error */
const char* mf_get_error(void) {
    return g_error_message;
}

/* Get version */
const char* mf_get_version(void) {
    static char version[32];
    snprintf(version, sizeof(version), "%d.%d.%d",
             MF_VERSION_MAJOR, MF_VERSION_MINOR, MF_VERSION_PATCH);
    return version;
}
