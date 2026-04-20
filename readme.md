# 🚀 Kapsule: Forensic Linux Container Runtime

## A Custom Linux Container Runtime Built From Scratch in C

Kapsule is a lightweight Linux container runtime written entirely in C from scratch, replicating the core mechanics of Docker/runc without using any external container libraries.

It isolates processes using raw Linux kernel primitives (**Namespaces, OverlayFS, cgroups v2**) and introduces a custom **Ghost Engine** — a post-exit forensic intelligence layer that no standard container runtime provides.

---

## ✨ Features

### 1. Core Kernel & Isolation Primitives

* **Namespaces**

  * Isolates PID, UTS (Hostname), Network, Mount, and IPC
  * Container is completely air-gapped from the host network

* **Filesystem Jail**

  * Uses `pivot_root` (stronger than `chroot`)
  * Backed by OverlayFS
  * Base Alpine Linux image remains strictly read-only

* **Resource Limits**

  * Enforces strict RAM limits (e.g., 10MB / 100MB)
  * Uses cgroups v2
  * Triggers kernel OOM Killer instantly if exceeded

---

### 👻 Ghost Engine (Forensic Pipeline)

* 📂 Filesystem Audit (OverlayFS diff)
* 🕵️ Behavioral Threat Scoring (via `ptrace`)
* ⏱️ Time-Bomb Detection (sleep syscall interception)
* 📜 Conditional Replay Log (triggered on high threat)

---

## 🏗️ System Architecture

| Module    | Responsibility                     |
| --------- | ---------------------------------- |
| module1.c | Namespaces + ptrace Threat Monitor |
| module2.c | pivot_root + OverlayFS Diff Engine |
| module3.c | cgroups v2 Resource Limits         |
| main.c    | Orchestration + Report Generation  |

---

## 💻 Prerequisites & OS Setup

Kapsule requires a modern Linux kernel.

---

### 🐧 Native Linux (Ubuntu/Debian)

```
sudo apt-get update
sudo apt-get install build-essential gcc make
```

---

### 🪟 Windows (WSL2)

⚠️ WSL1 will NOT work

1. Set WSL2:

   wsl --set-default-version 2

2. Install Ubuntu:

   wsl --install -d Ubuntu

3. Enable systemd:

   sudo nano /etc/wsl.conf

Add:

```
[boot]
systemd=true
```

4. Restart WSL:

```
wsl.exe --shutdown
```

5. Install build tools:

```
sudo apt-get install build-essential gcc make
```

---

### 🍎 macOS (Using VM)

```
brew install --cask multipass
multipass launch --name kapsule-vm
multipass shell kapsule-vm
sudo apt-get install build-essential gcc make
```

---

## 🚀 Installation & Build

```
git clone https://github.com/yourusername/kapsule.git
cd kapsule

mkdir -p rootfs container_work/upper container_work/work container_work/merged

cd rootfs
wget https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz
tar -xzf alpine-minirootfs-3.18.4-x86_64.tar.gz
rm alpine-minirootfs-3.18.4-x86_64.tar.gz
cd ..

make clean
make
```

---

## 🎮 Run

```
sudo ./kapsule
```

Try:

```
hostname
ps
touch /tmp/hello.txt
ping 8.8.8.8
```

Exit:

```
exit
```

---

## 🎬 Demo Scenarios

```
chmod +x demo1_clean.sh demo2_ransomware.sh demo3_timebomb.sh demo4_oom.sh
```

### 🟢 Clean

```
./demo1_clean.sh
```

### 🔴 Ransomware

```
./demo2_ransomware.sh
```

### 🟡 Time-Bomb

```
./demo3_timebomb.sh
```

### 🟣 OOM Attack

```
./demo4_oom.sh
```

---

## 🛠️ Troubleshooting

### cgroup error

```
wsl.exe --shutdown
```

### Permission denied

```
sudo rm -rf container_work/*
```

### pivot_root error

Ensure:

```
mkdir("oldroot", 0777);
```

---

## 🎓 Project

Systems Programming Capstone Project
