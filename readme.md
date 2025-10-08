# HRACS: Highly Reliable and Anonymous Cloud Synchronization

## Overview

**HRACS** is a password-based cloud storage (PBCS) scheme that enables secure dataset outsourcing and synchronization via password-based authentication. It simultaneously ensures **anonymity** (i.e., user activities cannot be linked to public identities) and **reliability** (i.e., users can detect any unauthorized modifications or rollback of their data).

---

## Implementation

- **Host environment**: Intel Core i7-9750H CPU (2.60 GHz), 16 GB RAM, Windows 11.  
- **Client environment** (virtualized via VMware Workstation 17): Ubuntu 20.04.2 LTS, 2 CPU cores, 8 GB RAM.  
- **Programming language**: C++17  
- **Compiler**: g++ 11.4.0  
- **Build system**: CMake 3.22.1  
- **Cryptographic libraries**: [PBC 0.5.14](https://github.com/blynn/pbc), [OpenSSL 3.0.2](https://github.com/openssl/openssl)  
- **Security parameter**: λ = 128  

---

## Build & Run

1. Navigate to the build directory:

```bash
cd Build
```

2. Generate build files with CMake:

```bash
cmake ..
```

3. Compile the code:

```bash
make
```

4. Run the executable with the parameter file:

```bash
./build < ../Param/a.param
```