#include "kapsule.h"

ThreatEvent replay_log[MAX_EVENTS];
int event_count = 0;
struct timespec start_time;

int child_payload(void *arg) {
    (void)arg;
    // sethostname: Set container hostname to 'kapsule'
    sethostname("kapsule", 7);
    setup_filesystem();
    
    // Tell parent we are ready to be traced
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    raise(SIGSTOP); // Pause so parent can attach

    char *args[] = {"/bin/sh", NULL};
    // execve: Spawn new binary launched
    execve("/bin/sh", args, NULL);
    
    perror("execve failed");
    return EXIT_FAILURE;
}

// Helper to get time elapsed in seconds
double get_elapsed_time() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start_time.tv_sec) + (now.tv_nsec - start_time.tv_nsec) / 1e9;
}

void start_ptrace_monitor(pid_t child_pid) {
    int status;
    long total_sleep_usec = 0;
    
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    // Wait for child to raise SIGSTOP
    waitpid(child_pid, &status, 0);
    
    // FIX: Trace all forks/clones so scripts and external commands cannot evade the sandbox
    ptrace(PTRACE_SETOPTIONS, child_pid, 0, 
           PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | 
           PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);

    // State tracker to distinguish between Syscall Entry and Syscall Exit for multiple processes
    pid_t traced_pids[1024];
    int in_syscall[1024] = {0};
    int pid_count = 1;
    traced_pids[0] = child_pid;

    // Resume the initial child process so it can execute /bin/sh
    ptrace(PTRACE_SYSCALL, child_pid, 0, 0);

    while (1) {
        // Wait for ANY traced process in the container
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid == -1) {
            if (errno == ECHILD) break;
            continue;
        }
        
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (pid == child_pid) break; // Main container shell exited
            continue; // A sub-process exited, keep monitoring the rest
        }

        // If the process stopped for a non-syscall reason (e.g., new fork event), resume it
        if (WSTOPSIG(status) != (SIGTRAP | 0x80)) {
            int sig = WSTOPSIG(status);
            // Suppress ptrace-specific SIGTRAPs, but forward genuine kernel signals (like SIGCHLD)
            int inject_sig = (sig == SIGTRAP) ? 0 : sig;
            ptrace(PTRACE_SYSCALL, pid, 0, inject_sig);
            continue;
        }

        // Find or register PID state
        int p_idx = -1;
        for (int i = 0; i < pid_count; i++) {
            if (traced_pids[i] == pid) { p_idx = i; break; }
        }
        if (p_idx == -1 && pid_count < 1024) {
            p_idx = pid_count++;
            traced_pids[p_idx] = pid;
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

                if (orig_rax == SYS_openat || orig_rax == SYS_open) { points = 5; strcpy(label, "FILE_READ"); }
                else if (orig_rax == SYS_write) { points = 10; strcpy(label, "FILE_WRITE"); }
                else if (orig_rax == SYS_unlink) { points = 20; strcpy(label, "FILE_DELETE"); }
                else if (orig_rax == SYS_execve) { points = 30; strcpy(label, "EXEC"); }
                else if (orig_rax == SYS_connect) { points = 50; strcpy(label, "NET_CONNECT"); }
                else if (orig_rax == SYS_nanosleep || orig_rax == SYS_clock_nanosleep || orig_rax == SYS_pause) { 
                    strcpy(label, "SLEEP");
                    points = 5; 
                    final_stats.timebomb_flag = 1; 
                    final_stats.sleep_ratio = 0.95; 
                    total_sleep_usec += 1000000; 
                }

                // Only log suspicious events to save memory
                if (points > 0 && event_count < MAX_EVENTS) {
                    final_stats.threat_score += points;
                    clock_gettime(CLOCK_MONOTONIC, &replay_log[event_count].timestamp);
                    replay_log[event_count].syscall_nr = orig_rax;
                    replay_log[event_count].threat_points = points;
                    strcpy(replay_log[event_count].label, label);
                    replay_log[event_count].tid = pid;
                    event_count++;
                }
            }
            // Flip state between entry/exit so we only log once per syscall
            in_syscall[p_idx] = !in_syscall[p_idx];
        }

        // Resume the specific process until its next syscall trap
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
    }

    // Finalize Timing stats
    // sleep_ratio = total_sleep_time / total_runtime
    double runtime_secs = get_elapsed_time();
    final_stats.sleep_ratio = (total_sleep_usec / 1e6) / (runtime_secs > 0 ? runtime_secs : 1);
    
    if (final_stats.sleep_ratio > 0.70 && runtime_secs > 5) {
        final_stats.timebomb_flag = 1;
    }
}