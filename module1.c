#include "kapsule.h"

ThreatEvent replay_log[MAX_EVENTS];
int event_count = 0;
struct timespec start_time;

int child_payload(void *arg) {
    (void)arg;
    sethostname("kapsule", 7);
    setup_filesystem();
    
    // HARD FAILSAFE: Prevent host swap thrashing if cgroup limits fail
    struct rlimit mem_limit;
    mem_limit.rlim_cur = 100 * 1024 * 1024; // 100 MB Limit
    mem_limit.rlim_max = 100 * 1024 * 1024;
    if (setrlimit(RLIMIT_AS, &mem_limit) != 0) {
        perror("setrlimit failed");
    }

    // Tell parent we are ready to be traced
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    raise(SIGSTOP); // Pause so parent can attach

    char *args[] = {"/bin/sh", NULL};
    execve("/bin/sh", args, NULL);
    
    perror("execve failed");
    return EXIT_FAILURE;
}

double get_elapsed_time() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
}

void start_ptrace_monitor(pid_t child_pid) {
    int status;
    long total_sleep_usec = 0;
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    waitpid(child_pid, &status, 0);
    
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, 
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
           PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);

    pid_t traced_pids[1024];
    int in_syscall[1024] = {0};
    struct timespec syscall_entry_time[1024]; // Track exact entry time per PID
    int pid_count = 1;
    traced_pids[0] = child_pid;

    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);

    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == ECHILD) break;
            continue;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child_pid) break; 
            continue; 
        }

        // Filter out non-syscall traps (like SIGSTOP or clone events)
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            int sig = WSTOPSIG(status);
            int inject_sig = (sig == SIGTRAP || sig == SIGSTOP) ? 0 : sig;
            ptrace(PTRACE_SYSCALL, pid, 0, inject_sig);
            continue;
        }

        int p_idx = -1;
        for (int i = 0; i < pid_count; i++) {
            if (traced_pids[i] == pid) { p_idx = i; break; }
        }
        
        if (p_idx == -1 && pid_count < 1024) {
            p_idx = pid_count++;
            traced_pids[p_idx] = pid;
            // CORRECTED: The first 0x80 trap is guaranteed to be a SYSCALL ENTRY.
            in_syscall[p_idx] = 0; 
        }

        if (p_idx != -1) {
            if (!in_syscall[p_idx]) {
                // === SYSCALL ENTRY ===
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                
                long orig_rax = regs.orig_rax;
                int points = 0;
                char label[32] = "UNKNOWN";

                // Record the exact time the syscall started
                clock_gettime(CLOCK_MONOTONIC, &syscall_entry_time[p_idx]);

                if (orig_rax == SYS_openat || orig_rax == SYS_open) { points = 1; strcpy(label, "FILE_OPEN"); }
                else if (orig_rax == SYS_write) { points = 2; strcpy(label, "FILE_WRITE"); }
                else if (orig_rax == SYS_unlink) { points = 20; strcpy(label, "FILE_DELETE"); }
                else if (orig_rax == SYS_execve) { points = 10; strcpy(label, "EXEC"); }
                else if (orig_rax == SYS_connect) { points = 50; strcpy(label, "NET_CONNECT"); }
                else if (orig_rax == SYS_nanosleep || orig_rax == SYS_clock_nanosleep || orig_rax == SYS_pause) { 
                    strcpy(label, "SLEEP");
                    points = 2; 
                }

                if (points > 0 && event_count < MAX_EVENTS) {
                    final_stats.threat_score += points;
                    clock_gettime(CLOCK_MONOTONIC, &replay_log[event_count].timestamp);
                    replay_log[event_count].syscall_nr = orig_rax;
                    replay_log[event_count].threat_points = points;
                    strcpy(replay_log[event_count].label, label);
                    replay_log[event_count].tid = pid;
                    event_count++;
                }
            } else {
                // === SYSCALL EXIT ===
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, pid, NULL, &regs);
                long orig_rax = regs.orig_rax;

                // Calculate the exact elapsed time for sleep syscalls
                if (orig_rax == SYS_nanosleep || orig_rax == SYS_clock_nanosleep || orig_rax == SYS_pause) {
                    struct timespec exit_time;
                    clock_gettime(CLOCK_MONOTONIC, &exit_time);
                    
                    long elapsed_usec = (exit_time.tv_sec - syscall_entry_time[p_idx].tv_sec) * 1000000 +
                                        (exit_time.tv_nsec - syscall_entry_time[p_idx].tv_nsec) / 1000;
                    
                    if (elapsed_usec > 0) {
                        total_sleep_usec += elapsed_usec;
                    }
                }
            }
            // Flip state between entry/exit so we only log once per syscall
            in_syscall[p_idx] = !in_syscall[p_idx];
        }

        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }

    // Finalize Timing stats
    double runtime_secs = get_elapsed_time();
    final_stats.sleep_ratio = (total_sleep_usec / 1e6) / (runtime_secs > 0 ? runtime_secs : 1);
    
    // Low-pass filter: Catch scripts that sleep heavily and run for > 1 sec
    if (final_stats.sleep_ratio > 0.70 && runtime_secs > 1.0) {
        final_stats.timebomb_flag = 1;
    }
}