#include "kapsule.h"

char cg_path[PATH_MAX];
int is_cgroup_v2 = 1;

void setup_cgroups() {
    snprintf(cg_path, sizeof(cg_path), "/tmp/cgroup_v2/kapsule_%d", getpid());

    mkdir("/tmp/cgroup_v2", 0755);
    mount("none", "/tmp/cgroup_v2", "cgroup2", 0, NULL);

    FILE *f_sub = fopen("/tmp/cgroup_v2/cgroup.subtree_control", "w");
    if (f_sub) {
        fprintf(f_sub, "+memory");
        fclose(f_sub);
    }

    if (mkdir(cg_path, 0755) && errno != EEXIST) { }

    char path[PATH_MAX + 256];
    snprintf(path, sizeof(path), "%s/memory.max", cg_path);
    if (access(path, F_OK) != 0) {
        is_cgroup_v2 = 0;
        snprintf(cg_path, sizeof(cg_path), "/sys/fs/cgroup/memory/kapsule_%d", getpid());
        if (mkdir(cg_path, 0755) && errno != EEXIST) {
            perror("Failed to create cgroup v1");
        }
    }

    if (is_cgroup_v2) {
        snprintf(path, sizeof(path), "%s/memory.max", cg_path);
        FILE *f = fopen(path, "w");
        if (f) { fprintf(f, "100000000"); fclose(f); }

        snprintf(path, sizeof(path), "%s/memory.swap.max", cg_path);
        FILE *f_swap = fopen(path, "w");
        if (f_swap) { fprintf(f_swap, "0"); fclose(f_swap); }
    } else {
        snprintf(path, sizeof(path), "%s/memory.limit_in_bytes", cg_path);
        FILE *f = fopen(path, "w");
        if (f) { fprintf(f, "100000000"); fclose(f); }

        snprintf(path, sizeof(path), "%s/memory.memsw.limit_in_bytes", cg_path);
        FILE *f_swap = fopen(path, "w");
        if (f_swap) { fprintf(f_swap, "100000000"); fclose(f_swap); }
    }
}

void add_pid_to_cgroup(pid_t pid) {
    char path[PATH_MAX + 256];
    if (is_cgroup_v2) {
        snprintf(path, sizeof(path), "%s/cgroup.procs", cg_path);
    } else {
        snprintf(path, sizeof(path), "%s/tasks", cg_path);
    }
    
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d", pid);
        fclose(f);
    } else {
        perror("Failed to add child to cgroup");
    }
}

void read_cgroup_stats() {
    char path[PATH_MAX + 256];
    char buffer[256];
    
    if (is_cgroup_v2) {
        snprintf(path, sizeof(path), "%s/memory.peak", cg_path);
        FILE *f = fopen(path, "r");
        if (f && fgets(buffer, sizeof(buffer), f)) {
            final_stats.peak_memory_bytes = atol(buffer);
            fclose(f);
        } else {
            snprintf(path, sizeof(path), "%s/memory.current", cg_path);
            FILE *fc = fopen(path, "r");
            if (fc && fgets(buffer, sizeof(buffer), fc)) {
                final_stats.peak_memory_bytes = atol(buffer);
                fclose(fc);
            }
        }

        snprintf(path, sizeof(path), "%s/memory.events", cg_path);
        f = fopen(path, "r");
        if (f) {
            while (fgets(buffer, sizeof(buffer), f)) {
                if (strncmp(buffer, "oom_kill", 8) == 0) {
                    int kills;
                    sscanf(buffer, "oom_kill %d", &kills);
                    if (kills > 0) {
                        final_stats.oom_killed = 1;
                        final_stats.peak_memory_bytes = 100000000;
                    }
                }
            }
            fclose(f);
        }
    } else {
        snprintf(path, sizeof(path), "%s/memory.max_usage_in_bytes", cg_path);
        FILE *f = fopen(path, "r");
        if (f && fgets(buffer, sizeof(buffer), f)) {
            final_stats.peak_memory_bytes = atol(buffer);
            fclose(f);
        }

        snprintf(path, sizeof(path), "%s/memory.oom_control", cg_path);
        f = fopen(path, "r");
        if (f) {
            while (fgets(buffer, sizeof(buffer), f)) {
                if (strncmp(buffer, "oom_kill", 8) == 0) {
                    int kills;
                    sscanf(buffer, "oom_kill %d", &kills);
                    if (kills > 0) {
                        final_stats.oom_killed = 1;
                        final_stats.peak_memory_bytes = 100000000;
                    }
                }
            }
            fclose(f);
        }
    }
}