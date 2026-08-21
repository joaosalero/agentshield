#define _POSIX_C_SOURCE 200809L
#include "agentshield/sensor.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static void set_error(char *out, size_t size, const char *message) {
    if (out && size) snprintf(out, size, "%s", message);
}

static int read_link(const char *path, char *out, size_t size) {
    ssize_t length = readlink(path, out, size - 1);
    if (length < 0) return -1;
    out[length] = '\0';
    return 0;
}

static int contains_ci(const char *text, const char *needle) {
    size_t n = strlen(needle);
    if (!n) return 1;
    for (; *text; ++text) {
        size_t i = 0;
        while (i < n && text[i] && tolower((unsigned char)text[i]) == tolower((unsigned char)needle[i])) ++i;
        if (i == n) return 1;
    }
    return 0;
}

static uint8_t credential_risk(const char *name) {
    static const char *known_non_secrets[] = {"DBUS_SESSION_BUS_ADDRESS"};
    static const char *critical[] = {"private_key", "secret_key", "master_key", "root_token"};
    static const char *high[] = {"token", "secret", "password", "passwd", "api_key", "apikey", "credential"};
    static const char *medium[] = {"auth", "cookie", "session", "key"};
    for (size_t i = 0; i < sizeof known_non_secrets / sizeof *known_non_secrets; ++i) if (strcmp(name, known_non_secrets[i]) == 0) return 0;
    for (size_t i = 0; i < sizeof critical / sizeof *critical; ++i) if (contains_ci(name, critical[i])) return 4;
    for (size_t i = 0; i < sizeof high / sizeof *high; ++i) if (contains_ci(name, high[i])) return 3;
    for (size_t i = 0; i < sizeof medium / sizeof *medium; ++i) if (contains_ci(name, medium[i])) return 2;
    return 0;
}

static int sensitive_path(const char *path) {
    static const char *patterns[] = {"/.ssh/", "/.aws/", "/.gnupg/", "/.kube/", "/.config/gh/", "/etc/shadow", ".env", "credentials", "id_rsa", "id_ed25519"};
    for (size_t i = 0; i < sizeof patterns / sizeof *patterns; ++i) if (contains_ci(path, patterns[i])) return 1;
    return 0;
}

static int parse_status(int pid, as_snapshot *snapshot) {
    char path[64], line[512];
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *file = fopen(path, "r");
    if (!file) return -1;
    while (fgets(line, sizeof line, file)) {
        if (sscanf(line, "Name:%255s", snapshot->process_name) == 1) continue;
        if (sscanf(line, "PPid:%d", &snapshot->parent_pid) == 1) continue;
        unsigned int real_uid = 0, effective_uid = 0, saved_uid = 0, filesystem_uid = 0;
        if (sscanf(line, "Uid:%u%u%u%u", &real_uid, &effective_uid, &saved_uid, &filesystem_uid) == 4) {
            snapshot->effective_uid = effective_uid;
            continue;
        }
        unsigned long long caps = 0;
        if (sscanf(line, "CapEff:%llx", &caps) == 1) snapshot->effective_capabilities = (uint64_t)caps;
    }
    fclose(file);
    return 0;
}

static int parse_environment(int pid, as_snapshot *snapshot) {
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/environ", pid);
    int file = open(path, O_RDONLY | O_CLOEXEC);
    if (file < 0) return -1;
    char name[AS_MAX_NAME];
    size_t name_length = 0;
    int reading_name = 1;
    unsigned char byte = 0;
    int read_failed = 0;
    for (;;) {
        ssize_t count = read(file, &byte, 1);
        if (count == 0) break;
        if (count < 0) { if (errno == EINTR) continue; read_failed = 1; break; }
        if (byte == '\0') {
            name_length = 0;
            reading_name = 1;
            continue;
        }
        if (reading_name && byte == '=') {
            name[name_length] = '\0';
            uint8_t risk = credential_risk(name);
            if (risk) {
                if (snapshot->credential_count < AS_MAX_ITEMS) {
                    as_credential *credential = &snapshot->credentials[snapshot->credential_count++];
                    snprintf(credential->name, sizeof credential->name, "%s", name);
                    credential->risk = risk;
                } else {
                    ++snapshot->truncated_items;
                }
            }
            memset(name, 0, sizeof name);
            reading_name = 0;
        } else if (reading_name) {
            if (name_length < sizeof name - 1) name[name_length++] = (char)byte;
            else ++snapshot->truncated_items;
        }
        if (!reading_name) byte = 0;
    }
    memset(name, 0, sizeof name);
    byte = 0;
    close(file);
    return read_failed ? -1 : 0;
}

static unsigned long long process_start_time(int pid) {
    char path[64], line[4096];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *file = fopen(path, "r");
    if (!file) return 0;
    if (!fgets(line, sizeof line, file)) { fclose(file); return 0; }
    fclose(file);
    char *cursor = strrchr(line, ')');
    if (!cursor) return 0;
    ++cursor;
    for (int field = 3; field <= 22; ++field) {
        while (*cursor == ' ') ++cursor;
        char *end = cursor;
        while (*end && *end != ' ') ++end;
        if (field == 22) return strtoull(cursor, NULL, 10);
        cursor = end;
    }
    return 0;
}

static int parse_resources(int pid, as_snapshot *snapshot) {
    char directory_path[64];
    snprintf(directory_path, sizeof directory_path, "/proc/%d/fd", pid);
    DIR *directory = opendir(directory_path);
    if (!directory) return -1;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        char link_path[AS_MAX_PATH], target[AS_MAX_PATH];
        snprintf(link_path, sizeof link_path, "%s/%s", directory_path, entry->d_name);
        if (read_link(link_path, target, sizeof target) != 0) continue;
        as_resource_kind kind = AS_RESOURCE_FILE;
        uint8_t risk = 0;
        if (strncmp(target, "socket:[", 8) == 0) { kind = AS_RESOURCE_SOCKET; risk = 2; }
        else if (strncmp(target, "pipe:[", 6) == 0) kind = AS_RESOURCE_PIPE;
        else if (target[0] != '/') kind = AS_RESOURCE_OTHER;
        else if (sensitive_path(target)) { kind = AS_RESOURCE_SENSITIVE_FILE; risk = 3; }
        if (!risk) continue;
        if (snapshot->resource_count < AS_MAX_ITEMS) {
            as_resource *resource = &snapshot->resources[snapshot->resource_count++];
            snprintf(resource->path, sizeof resource->path, "%s", target);
            resource->kind = kind;
            resource->risk = risk;
        } else ++snapshot->truncated_items;
    }
    closedir(directory);
    return 0;
}

int as_collect_snapshot(int pid, as_snapshot *snapshot, char *error, size_t error_size) {
    if (!snapshot || pid <= 0) { set_error(error, error_size, "invalid arguments"); return -1; }
    memset(snapshot, 0, sizeof *snapshot);
    snapshot->pid = pid;
    unsigned long long identity_before = process_start_time(pid);
    char proc_path[64];
    snprintf(proc_path, sizeof proc_path, "/proc/%d", pid);
    if (access(proc_path, R_OK) != 0) { set_error(error, error_size, errno == ENOENT ? "process not found" : "process metadata is not readable"); return -1; }
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/exe", pid); read_link(path, snapshot->executable, sizeof snapshot->executable);
    snprintf(path, sizeof path, "/proc/%d/cwd", pid); read_link(path, snapshot->working_directory, sizeof snapshot->working_directory);
    if (parse_status(pid, snapshot) == 0) snapshot->coverage |= AS_COVERAGE_STATUS;
    if (parse_environment(pid, snapshot) == 0) snapshot->coverage |= AS_COVERAGE_ENVIRONMENT;
    if (parse_resources(pid, snapshot) == 0) snapshot->coverage |= AS_COVERAGE_RESOURCES;
    unsigned long long identity_after = process_start_time(pid);
    if (!identity_before || identity_before != identity_after) {
        memset(snapshot, 0, sizeof *snapshot);
        set_error(error, error_size, "process identity changed during collection");
        return -1;
    }
    set_error(error, error_size, "");
    return 0;
}

const char *as_resource_kind_name(as_resource_kind kind) {
    switch (kind) {
        case AS_RESOURCE_FILE: return "file";
        case AS_RESOURCE_SENSITIVE_FILE: return "sensitive_file";
        case AS_RESOURCE_SOCKET: return "network_socket";
        case AS_RESOURCE_PIPE: return "pipe";
        default: return "other";
    }
}
