# Deployment Guide for Target Core

Follow these steps to build target_core, upload it to the VPS, and restart the service.

## Troubleshooting Quick Fixes

### 1. scp failed with "dest open Failure"
If you get `C:\WINDOWS\System32\OpenSSH\scp.exe: dest open "/root/target_core": Failure`, it means target_core is currently running on the VPS and Linux is locking the executable. 
**Fix:** You must stop/kill target_core on the VPS before uploading:
```bash
ssh root@139.59.104.63 "pkill target_core"
```

### 2. WSL command not found: cargo
If you get `cargo: command not found` in WSL, run the following in WSL to install the Rust compiler and toolchain (use `sudo -E` to preserve proxy environment variables if using Nekobox TUN mode):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Or install it via apt:
```bash
sudo -E apt update && sudo -E apt install -y cargo rustc
```

### 3. WSL command not found: scp / ssh
If you get `scp: command not found` or `ssh: command not found` in WSL, run the following inside WSL to install OpenSSH tools (using `sudo -E` to preserve proxy variables):
```bash
sudo -E apt update && sudo -E apt install -y openssh-client
```

---

## Step-by-Step Deployment

### Step 1: Stop target_core on the VPS
```bash
ssh root@139.59.104.63 "pkill target_core"
```

### Step 2: Build the Linux binary in WSL
Open WSL and run:
```bash
cd /mnt/c/Users/Heshan/Desktop/Ruve/target_core
cargo build --release
```
The compiled Linux binary is generated at `target/release/target_core`.

### Step 3: Upload the binary to the VPS
If WSL has proxy/SSH connection issues, you can run the `scp` command from a standard **Windows PowerShell** terminal (since the files compiled in WSL are shared and located at `C:\Users\Heshan\Desktop\Ruve\target_core\target\release\target_core`):

**In Windows PowerShell:**
```powershell
scp target_core/target/release/target_core root@139.59.104.63:/root/
```

*(Or inside WSL if openSSH is working: `scp target/release/target_core root@139.59.104.63:/root/`)*

### Step 4: Start target_core on the VPS
Run from **Windows PowerShell** (or WSL):
```bash
ssh root@139.59.104.63 "nohup /root/target_core > /root/target_core.log 2>&1 &"
```

### Step 5: Verify it is running
* **Check process status:**
```bash
ssh root@139.59.104.63 "ps aux | grep target_core"
```

* **View live logs:**
```bash
ssh root@139.59.104.63 "tail -f /root/target_core.log"
```
