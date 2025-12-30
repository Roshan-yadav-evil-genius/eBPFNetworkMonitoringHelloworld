# Python BPF Setup and Usage Guide

## Overview

This guide explains how to set up and run the cgroup monitoring scripts using Python BPF. For detailed documentation, refer to the [python-bpf GitHub repository](https://github.com/pythonbpf/python-bpf).

## Prerequisites

- Python 3.x installed
- sudo/root access (required for BPF programs)
- Linux system with BPF support

## Installation

### 1. Install Python BPF

```bash
pip install pythonbpf
```

### 2. Install Clang (Required for BPF compilation)

```bash
sudo pip3 install clang==18.* --break-system-packages
```

### 3. Generate vmlinux Header
clone and use below command to generate vmlinux [python-bpf GitHub repository](https://github.com/pythonbpf/python-bpf)

Resources: 
https://www.youtube.com/watch?v=eFVhLnWFxtE
```bash
# 
sudo tools/vmlinux-gen.py
```

## Running the Monitors

### Execute cgroup_monitor.py or simple_cgroup_monitor.py

```bash
sudo $(which python) cgroup_monitor.py
```

or

```bash
sudo $(which python) simple_cgroup_monitor.py
```

## File Differences

### cgroup_monitor.py
- **Features**: Network I/O, File I/O, CPU tracking, Memory tracking
- **Additional Data Sources**: Reads from cgroup filesystem
  - `cpu.stat` - CPU usage statistics
  - `memory.current` - Current memory usage
  - `memory.max` - Memory limits

### simple_cgroup_monitor.py
- **Features**: Network I/O, File I/O
- **Data Source**: BPF only (no cgroup filesystem reads)

## Reference

For more detailed information, see the [python-bpf README](https://github.com/pythonbpf/python-bpf).
