#include "kapsule.h"

// Note: Using your WSL-specific cgroup path
#define CGROUP_PATH "/sys/fs/cgroup/unified/kapsule"

void setup_cgroups() {
    if (mkdir(CGROUP_PATH, 0755) && errno != EEXIST) {
        perror("Failed to create cgroup");
        return; 
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/memory.max", CGROUP_PATH);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "100000000"); // 100MB limit
        fclose(f);
    }

    // ---> NEW: Disable Swap Space <---
    // This forces the OOM killer to fire instantly when 100MB is breached, 
    // instead of the system freezing to write memory to disk.
    snprintf(path, sizeof(path), "%s/memory.swap.max", CGROUP_PATH);
    FILE *f_swap = fopen(path, "w");
    if (f_swap) {
        fprintf(f_swap, "0");
        fclose(f_swap);
    }

    snprintf(path, sizeof(path), "%s/cgroup.procs", CGROUP_PATH);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "%d", getpid());
        fclose(f);
    }
}

void read_cgroup_stats() {
    char path[PATH_MAX];
    char buffer[256];
    
    // Read Peak Memory [cite: 271]
    snprintf(path, sizeof(path), "%s/memory.peak", CGROUP_PATH);
    FILE *f = fopen(path, "r");
    if (f && fgets(buffer, sizeof(buffer), f)) {
        final_stats.peak_memory_bytes = atol(buffer);
        fclose(f);
    } else {
        // Fallback for older kernels (like WSL2's 5.15) which lack memory.peak
        snprintf(path, sizeof(path), "%s/memory.current", CGROUP_PATH);
        FILE *fc = fopen(path, "r");
        if (fc && fgets(buffer, sizeof(buffer), fc)) {
            final_stats.peak_memory_bytes = atol(buffer);
            fclose(fc);
        }
    }

    // Check OOM Killer events [cite: 220]
    snprintf(path, sizeof(path), "%s/memory.events", CGROUP_PATH);
    f = fopen(path, "r");
    if (f) {
        while (fgets(buffer, sizeof(buffer), f)) {
            if (strncmp(buffer, "oom_kill", 8) == 0) {
                int kills;
                sscanf(buffer, "oom_kill %d", &kills);
                if (kills > 0) {
                    final_stats.oom_killed = 1;
                    final_stats.peak_memory_bytes = 100000000; // Hardcode max limit if OOM fired
                }
            }
        }
        fclose(f);
    }
}