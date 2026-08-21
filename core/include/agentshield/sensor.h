#ifndef AGENTSHIELD_SENSOR_H
#define AGENTSHIELD_SENSOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AS_MAX_NAME 256
#define AS_MAX_PATH 1024
#define AS_MAX_ITEMS 128
#define AS_COVERAGE_STATUS 1U
#define AS_COVERAGE_ENVIRONMENT 2U
#define AS_COVERAGE_RESOURCES 4U

typedef enum {
    AS_RESOURCE_FILE = 1,
    AS_RESOURCE_SENSITIVE_FILE = 2,
    AS_RESOURCE_SOCKET = 3,
    AS_RESOURCE_PIPE = 4,
    AS_RESOURCE_OTHER = 5
} as_resource_kind;

typedef struct {
    char name[AS_MAX_NAME];
    uint8_t risk;
} as_credential;

typedef struct {
    char path[AS_MAX_PATH];
    as_resource_kind kind;
    uint8_t risk;
} as_resource;

typedef struct {
    int pid;
    int parent_pid;
    unsigned int effective_uid;
    uint64_t effective_capabilities;
    char process_name[AS_MAX_NAME];
    char executable[AS_MAX_PATH];
    char working_directory[AS_MAX_PATH];
    as_credential credentials[AS_MAX_ITEMS];
    size_t credential_count;
    as_resource resources[AS_MAX_ITEMS];
    size_t resource_count;
    size_t truncated_items;
    uint32_t coverage;
} as_snapshot;

/* Credential values are discarded during parsing and never retained in the snapshot. */
int as_collect_snapshot(int pid, as_snapshot *snapshot, char *error, size_t error_size);
const char *as_resource_kind_name(as_resource_kind kind);

#ifdef __cplusplus
}
#endif

#endif
