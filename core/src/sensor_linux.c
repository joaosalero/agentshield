#define _POSIX_C_SOURCE 200809L
#include "agentshield/sensor.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
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

static const char *tcp_state(unsigned int state) {
    static const char *states[] = {"UNKNOWN","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1","FIN_WAIT2","TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING","NEW_SYN_RECV"};
    return state < sizeof states / sizeof *states ? states[state] : "UNKNOWN";
}

static int decode_endpoint(const char *encoded, int ipv6, char *out, size_t size) {
    const char *separator = strrchr(encoded, ':');
    if (!separator || separator == encoded) return -1;
    unsigned int port = 0;
    if (sscanf(separator + 1, "%x", &port) != 1 || port > 65535) return -1;
    char address[INET6_ADDRSTRLEN];
    if (!ipv6) {
        if ((size_t)(separator - encoded) != 8) return -1;
        unsigned int raw = 0;
        if (sscanf(encoded, "%8x", &raw) != 1) return -1;
        struct in_addr ipv4 = { .s_addr = raw };
        if (!inet_ntop(AF_INET, &ipv4, address, sizeof address)) return -1;
        snprintf(out, size, "%s:%u", address, port);
        return 0;
    }
    if ((size_t)(separator - encoded) != 32) return -1;
    unsigned char bytes[16];
    for (size_t word = 0; word < 4; ++word) {
        unsigned int raw = 0;
        if (sscanf(encoded + word * 8, "%8x", &raw) != 1) return -1;
        memcpy(bytes + word * 4, &raw, 4);
    }
    if (!inet_ntop(AF_INET6, bytes, address, sizeof address)) return -1;
    snprintf(out, size, "[%s]:%u", address, port);
    return 0;
}

static void apply_socket_table(int pid, const char *table, const char *protocol, int ipv6, int tcp, as_snapshot *snapshot) {
    char path[64], line[1024];
    snprintf(path, sizeof path, "/proc/%d/net/%s", pid, table);
    FILE *file = fopen(path, "r");
    if (!file) return;
    if (!fgets(line, sizeof line, file)) { fclose(file); return; }
    while (fgets(line, sizeof line, file)) {
        char local[80], remote[80];
        unsigned int state = 0;
        unsigned long long inode = 0;
        int parsed = sscanf(line, " %*u: %79s %79s %2x %*s %*s %*s %*u %*u %llu", local, remote, &state, &inode);
        if (parsed != 4) continue;
        for (size_t index = 0; index < snapshot->resource_count; ++index) {
            as_resource *resource = &snapshot->resources[index];
            if (resource->kind != AS_RESOURCE_SOCKET || resource->socket_inode != inode || resource->network_protocol[0]) continue;
            snprintf(resource->network_protocol, sizeof resource->network_protocol, "%s", protocol);
            if (decode_endpoint(local, ipv6, resource->local_endpoint, sizeof resource->local_endpoint) != 0) resource->local_endpoint[0] = '\0';
            if (decode_endpoint(remote, ipv6, resource->remote_endpoint, sizeof resource->remote_endpoint) != 0) resource->remote_endpoint[0] = '\0';
            snprintf(resource->connection_state, sizeof resource->connection_state, "%s", tcp ? tcp_state(state) : state == 7 ? "UNCONNECTED" : "ACTIVE");
        }
    }
    fclose(file);
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

static void parse_cgroup(int pid, as_snapshot *snapshot) {
    char path[64], line[AS_MAX_PATH + 16];
    snprintf(path, sizeof path, "/proc/%d/cgroup", pid);
    FILE *file = fopen(path, "r");
    if (!file) return;
    while (fgets(line, sizeof line, file)) {
        if (strncmp(line, "0::/", 4) != 0) continue;
        char *value = line + 3;
        value[strcspn(value, "\r\n")] = '\0';
        size_t length = strnlen(value, sizeof snapshot->cgroup_path - 1);
        memcpy(snapshot->cgroup_path, value, length);
        snapshot->cgroup_path[length] = '\0';
        break;
    }
    fclose(file);
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
        unsigned long long socket_inode = 0;
        if (sscanf(target, "socket:[%llu]", &socket_inode) == 1) { kind = AS_RESOURCE_SOCKET; risk = 2; }
        else if (strncmp(target, "pipe:[", 6) == 0) kind = AS_RESOURCE_PIPE;
        else if (target[0] != '/') kind = AS_RESOURCE_OTHER;
        else if (sensitive_path(target)) { kind = AS_RESOURCE_SENSITIVE_FILE; risk = 3; }
        if (!risk) continue;
        if (snapshot->resource_count < AS_MAX_ITEMS) {
            as_resource *resource = &snapshot->resources[snapshot->resource_count++];
            snprintf(resource->path, sizeof resource->path, "%s", target);
            resource->kind = kind;
            resource->risk = risk;
            resource->socket_inode = socket_inode;
        } else ++snapshot->truncated_items;
    }
    closedir(directory);
    apply_socket_table(pid, "tcp", "tcp", 0, 1, snapshot);
    apply_socket_table(pid, "tcp6", "tcp6", 1, 1, snapshot);
    apply_socket_table(pid, "udp", "udp", 0, 0, snapshot);
    apply_socket_table(pid, "udp6", "udp6", 1, 0, snapshot);
    for (size_t index = 0; index < snapshot->resource_count; ++index) {
        as_resource *resource = &snapshot->resources[index];
        if (resource->kind != AS_RESOURCE_SOCKET || !resource->network_protocol[0]) continue;
        const char *endpoint = resource->remote_endpoint;
        if (!endpoint[0] || strcmp(endpoint, "0.0.0.0:0") == 0 || strcmp(endpoint, "[::]:0") == 0) endpoint = resource->local_endpoint;
        if (endpoint[0]) {
            char identifier[AS_MAX_PATH];
            snprintf(identifier, sizeof identifier, "%s://%s", resource->network_protocol, endpoint);
            snprintf(resource->path, sizeof resource->path, "%s", identifier);
        }
    }
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
    parse_cgroup(pid, snapshot);
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
