# xexemu

Structural/semantic analysis of xex under hypervisor enforced code signing. This is a xex2 parser/loader emulator. xex2 is the proprietary executable container used on the Zbox 360 for wrapping compressed/encrypted PE images with headers encoding signing certificates, capability flags, allowed media types, title keyvault bindings and import resolution metadata

The hypervisor verifies the RSA signature on the xex header before permitting execution and the kernel loader handles segment mapping as well as import thunk patching and TLS initialisation. This project instruments the loader logic to understand exactly what the kernel validates at load time vs what the hypervisor validates since those 2 verification passes have different threat models

## Building

```bash
mkdir build && cd build
cmake ..
make
```

## Usage

```bash
./xexemu <xex_file> [--verify] [--load]
```

### Examples

Basic analysis:

```bash
./xexemu skyrim.xex
```

Full analysis with verification/loader emulation:

```bash
./xexemu fallout.xex --verify --load
```