#include "kapsule.h"

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];

ResourceStats final_stats = {0};

void print_audit_report() {
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║            KAPSULE FORENSIC AUDIT REPORT                   ║\n");
    printf("╠════════════════════════════════════════════════════════════╣\n");
    
    // 1. Establish the base syscall verdict
    if (final_stats.threat_score <= 50) strcpy(final_stats.verdict, "\033[0;32mCLEAN\033[0m");
    else if (final_stats.threat_score <= 100) strcpy(final_stats.verdict, "\033[0;33mSUSPICIOUS\033[0m");
    else if (final_stats.threat_score <= 150) strcpy(final_stats.verdict, "\033[0;31mHIGH RISK\033[0m");
    else strcpy(final_stats.verdict, "\033[1;31mMALICIOUS ☠\033[0m");

    // 2. Apply Systemic Overrides without downgrading severe scores
    if (final_stats.oom_killed) {
        // OOM is always an immediate lethal threat
        strcpy(final_stats.verdict, "\033[1;31mMALICIOUS ☠ (OOM TRIGGERED)\033[0m");
    } else if (final_stats.timebomb_flag) {
        if (final_stats.threat_score > 150) {
            // Append the flag if it was already malicious
            strcpy(final_stats.verdict, "\033[1;31mMALICIOUS ☠ (+TIMEBOMB)\033[0m");
        } else {
            // Upgrade to High Risk if the syscall score was low
            strcpy(final_stats.verdict, "\033[0;31mHIGH RISK (TIMEBOMB)\033[0m");
        }
    }

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" FILESYSTEM CHANGES\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    for (int i = 0; i < fs_change_count; i++) {
        char *type_str = (fs_changes[i].type == DELETED) ? "DELETED" : "CREATED/MODIFIED";
        printf(" %s\t[%s]\t%ld B\n", fs_changes[i].path, type_str, fs_changes[i].size_bytes);
    }
    if (fs_change_count == 0) printf(" No filesystem changes detected.\n");

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" BEHAVIORAL THREAT ANALYSIS\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" THREAT SCORE:  %d / 100\n", final_stats.threat_score);
    printf(" VERDICT:       %s\n", final_stats.verdict);

    if (final_stats.timebomb_flag) {
        printf("\n ⚠ TIME-BOMB PATTERN DETECTED (Sleep Ratio: %.0f%%)\n", final_stats.sleep_ratio * 100);
    }

    // 3. Removed the conditional wrapper. Replay log prints unconditionally.
    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" REPLAY LOG\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    for (int i = 0; i < event_count; i++) {
        printf(" pid=%d\t%-15s\t+%d pts\n", 
               replay_log[i].tid, replay_log[i].label, replay_log[i].threat_points);
    }
    if (event_count == 0) printf(" No significant syscalls traced.\n");

    printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" RESOURCE USAGE\n");
    printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    printf(" Peak Memory:    %ld Bytes\n", final_stats.peak_memory_bytes);
    printf(" OOM Killed:     %s\n", final_stats.oom_killed ? "YES" : "NO");
    printf("╚════════════════════════════════════════════════════════════╝\n");
}

int main() {
    printf("Starting Kapsule Engine...\n");

    setup_cgroups();

    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWNS | SIGCHLD;
    pid_t child_pid = clone(child_payload, child_stack + STACK_SIZE, flags, NULL);

    if (child_pid == -1) {
        perror("clone failed"); exit(EXIT_FAILURE);
    }

    add_pid_to_cgroup(child_pid);

    start_ptrace_monitor(child_pid);
    audit_filesystem();
    read_cgroup_stats();
    print_audit_report();
    
    return 0;
}