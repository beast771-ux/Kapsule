#include "kapsule.h"

FileChange fs_changes[MAX_CHANGES];
int fs_change_count = 0;

void setup_filesystem() {
    if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) == -1) {
        perror("mount MS_PRIVATE failed"); exit(EXIT_FAILURE);
    }

    if (mount("overlay", "container_work/merged", "overlay", 0, 
              "lowerdir=rootfs,upperdir=container_work/upper,workdir=container_work/work") == -1) {
        perror("OverlayFS mount failed"); exit(EXIT_FAILURE);
    }

    chdir("container_work/merged");
    mkdir("oldroot", 0777);

    if (syscall(SYS_pivot_root, ".", "oldroot") == -1) {
        perror("pivot_root failed"); exit(EXIT_FAILURE);
    }

    chdir("/");
    umount2("/oldroot", MNT_DETACH);
}

// Callback for nftw() file walker
int diff_walker(const char *fpath, const struct stat *sb, int tflag, struct FTW *ftwbuf) {
    (void)sb; (void)tflag; // Unused
    (void)ftwbuf;
    
    // Skip the root upper folder itself
    if (strcmp(fpath, "container_work/upper") == 0) return 0;
    if (fs_change_count >= MAX_CHANGES) return 0;

    // Strip "container_work/upper" from path for clean output
    const char *clean_path = fpath + 20; 
    
    // Check for OverlayFS whiteout files (Deletions) [cite: 65]
    char *filename = strrchr(fpath, '/');
    if (filename && strncmp(filename + 1, ".wh.", 4) == 0) {
        fs_changes[fs_change_count].type = DELETED;
        snprintf(fs_changes[fs_change_count].path, PATH_MAX, "%s", clean_path);
    } else {
        // Simple logic: Assume CREATED/MODIFIED if it exists in upper/
        fs_changes[fs_change_count].type = CREATED; 
        fs_changes[fs_change_count].size_bytes = sb->st_size;
        snprintf(fs_changes[fs_change_count].path, PATH_MAX, "%s", clean_path);
    }
    
    fs_change_count++;
    return 0; // Continue walking
}

void audit_filesystem() {
    // Walk the upper/ directory to find what the container changed [cite: 57]
    nftw("container_work/upper", diff_walker, 20, FTW_PHYS);
}