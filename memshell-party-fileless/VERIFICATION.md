# Native Instrumentation verification

- Date: 2026-10-28.
- Every passing check runs without `-javaagent`, performs two fresh dynamic acquisitions, verifies byte-for-byte restoration of every patched region after each acquisition, checks redefine/retransform capabilities, and uses `addTransformer(..., true)` plus `retransformClasses` to change `Target.value()` from 7 to 8.
- The patch locations below come from independent ELF symbol inspection. They are restoration oracles only; production acquisition receives no address arguments and resolves the mapped runtime on every invocation.
- Local amd64 checks on macOS arm64 explicitly use `linux/amd64`. Remote amd64 checks run on Linux x86_64. ARM64 checks run natively on `linux/arm64`.

## Final double-patch regression

All seven current regressions print `NATIVE_JPLIS_RETRANSFORM_OK`.

| Image | Runtime and platform | Independent restoration oracle | Result |
| --- | --- | --- | --- |
| `jboss/wildfly:9.0.1.Final` | HotSpot `1.8.0_191-b12`, local amd64; stripped `libinstrument.so` | `libinstrument.so:0x5320` capacity 840; trigger `0x1de0` capacity 16 | PASS |
| `harbor.corp.boundaryx.net/cloudrasp/tomcat:8.5.97-jdk8` | HotSpot `1.8.0_342-b07`, remote amd64 | `libinstrument.so:0x3440` capacity 847; trigger `0x1e40` capacity 16 | PASS |
| `ibm-semeru-runtimes:open-25-jdk` (remote mirror) | OpenJ9 `25.0.3+9-LTS`, remote amd64 | `libjclse29.so:0x18bc0` capacity 815 | PASS |
| `eclipse-temurin:8-jre` | HotSpot `1.8.0_504-b01`, native arm64 | `libinstrument.so:0x52f8` capacity 828; trigger `0x1da8` capacity 12 | PASS |
| `open-liberty:25.0.0.12-full-java17-openj9` | OpenJ9 `0.61.0`, runtime `{{IP_4sdkqdps}}+1`, native arm64 | `libjclse29.so:0x19cc0` capacity 864 | PASS |
| `local/oracle-jdk:8u202` | Oracle HotSpot `1.8.0_202-b08`, local amd64 | `libinstrument.so:0x50e0` capacity 828; trigger `0x1d60` capacity 16 | PASS |
| `local/oracle-jdk:11.0.2` | Oracle HotSpot `11.0.2+9-LTS`, local amd64 | `libinstrument.so:0x5600` capacity 828; trigger `0x1e90` capacity 16 | PASS |

The WildFly case recovers the stripped JPLIS call graph and exact `.eh_frame` function ranges before any native write. The two Oracle checks were rerun against the final dual-region HotSpot implementation; both independently verify restoration of the host stub and JNI trigger after each acquisition.

These results are not a version allowlist. Other builds still require successful runtime resolution. Missing or ambiguous symbols, inconsistent mappings or layouts, unsupported ELF encodings, and missing trigger functions reject before native modification. No result here implies Windows, 32-bit ARM, or stripped ARM64 support.
