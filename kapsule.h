#ifndef KAPSULE_H
#define KAPSULE_H

#define _GNU_SOURCE
#define _XOPEN_SOURCE 500 // Required for nftw()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h> // REQUIRED FOR rlimit
#include <fcntl.h>
#include <ftw.h>
#include <time.h>
#include <limits.h>

// Shared Enums and Structs
typedef enum { CREATED, MODIFIED, DELETED } ChangeType;

typedef struct {
    char path[PATH_MAX];
    ChangeType type;
    off_t size_bytes;
} FileChange;

typedef struct {
    struct timespec timestamp;
    int syscall_nr;
    int threat_points;
    char label[32];
    pid_t tid;
} ThreatEvent;

typedef struct {
    long peak_memory_bytes;
    long cpu_time_usec;
    int oom_killed;
    double sleep_ratio;
    int timebomb_flag;
    int threat_score;
    char verdict[64];
} ResourceStats;

// Global Data Collection Arrays
#define MAX_CHANGES 100
#define MAX_EVENTS 1000

extern FileChange fs_changes[MAX_CHANGES];
extern int fs_change_count;

extern ThreatEvent replay_log[MAX_EVENTS];
extern int event_count;

extern ResourceStats final_stats;
extern struct timespec start_time;

// Function prototypes
int child_payload(void *arg);
void setup_cgroups();
void add_pid_to_cgroup(pid_t pid);
void read_cgroup_stats();
void setup_filesystem();
void audit_filesystem();
void start_ptrace_monitor(pid_t child_pid);

#endif