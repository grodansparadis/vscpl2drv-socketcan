# Changes in vscpl2drv-socketcan

Every change that goes into a release is listed here, newest release first.
Add each change under **Unreleased** when it is made. When a release is
tagged, rename **Unreleased** to the version and date, and start a new
**Unreleased** section above it.

## Unreleased

- Build the VSCP helper logging sources (vscphelperlogging.cpp and the forwarder), which vscphelper.cpp needs since the latest vscp
- Build against the latest vscp master (d75d4f5c6)
- Man page vscpl2drv-socketcan(1) describes the driver and its configuration file. It is converted from man/vscpl2drv-socketcan.1.md with pandoc when the driver is built and installed in share/man/man1; old man page scripts and generated files are removed
- Fix the driver failing to load: link the VSCP helper sources and expat, and fail the build on unresolved symbols
- Fix a crash and garbage frames: queue a copy of events passed to VSCPWrite instead of the caller's pointer
- Honour the `write` option and the out-filter; read full CAN FD frames and ignore RTR/error frames
- Fix the CI checksum step: readable SHA256SUMS files, bash 3.2 on macOS, and jobs that run in a subfolder
- Add scripts/download-artifacts.sh to download and verify the newest CI build artifacts
- CI writes a SHA256SUMS-<artifact> checksum file into every uploaded build artifact
- Fixed typo (6fed30a)
- Removed junk (647d0bd)
- cguid added to build (b53a858)
- Added workflow badges (337e95e)
- new version schema (2b203bc)
- RPi build added (5eb45d8)
- Updated to new build structure (3739385)

## v15.0.0 - 2021-07-01

- Added helper (b4317ae)
- Fixed config name fault (467ba06)
- Fixed action workflow build script (a8c339c)
- Fixed interface name debug output (cfb39f6)
- First version of documentation fixed (e530618)
- Clean compile (416d876)
- Prepare for 15 releae (f914ea2)
- Updated funding (bc8130c)
- Updated copyright (89a035c)
- Added vscp as submodule (db0021f)
- Fixed static lib (7668d11)
- Added dist to gitignore (8190ce2)
- Fixed recursive build (a30717b)
- Changed lib (b21fc32)
- added openssl as dependency (b100933)
- deb file and make install in sync (66e9c96)
- Reverted to old install structure (2721686)
- New version system (b780814)
- New version system (f543b04)
- New version handling (407a430)
- Fixed readme and man (de72917)
- Debian package builds (7bc305c)
- Now compiles again (d3bbd6b)
- Initial checkin after move (0248980)
- Initial commit (d96836f)
