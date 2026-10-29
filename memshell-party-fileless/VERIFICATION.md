# Native Instrumentation verification

- Date: 2026-10-28 to 2026-10-29.
- Every native fixture pass runs without `-javaagent`, performs two fresh dynamic acquisitions, verifies byte-for-byte restoration of every patched region after each acquisition, checks redefine/retransform capabilities, and uses `addTransformer(..., true)` plus `retransformClasses` to change `Target.value()` from 7 to 8.
- The packed Windows fixture separately defines and instantiates the real `FilelessAgentPacker` output without `-javaagent` or a fileless runtime on its class path, then verifies in-memory Agent installation and the same 7-to-8 retransformation.
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

These results are not a version allowlist. Other builds still require successful runtime resolution. Missing or ambiguous symbols, inconsistent mappings or layouts, unsupported ELF encodings, and missing trigger functions reject before native modification. No result here implies 32-bit ARM or stripped ARM64 support.

## Windows x64 native and packed-delivery regression

All seven native runs print `WINDOWS_NATIVE_JPLIS_RETRANSFORM_OK`. All seven packed runs print `WINDOWS_PACKED_FILELESS_RETRANSFORM_OK` and exit with status 0. The packed JAR contains only the fixture classes and the real packed bootstrap resource; the relocated fileless runtime is defined solely from that bootstrap.

| HotSpot runtime | Native double acquisition and restoration | Real packed bootstrap and retransform |
| --- | --- | --- |
| Oracle JDK `1.6.0_45-b06` | PASS | PASS |
| Oracle JDK `1.8.0_202-b08` | PASS | PASS |
| Oracle JDK `1.8.0_321-b07` | PASS | PASS |
| Oracle JDK `1.8.0_331-b09` | PASS | PASS |
| Oracle JDK `1.8.0_503-b01` | PASS | PASS |
| Oracle JDK `11.0.9+7-LTS` | PASS | PASS |
| Oracle JDK `17.0.3+8-LTS-111` | PASS | PASS |

The native fixture captures the dynamically resolved host and trigger regions before either acquisition and compares every byte after each acquisition. Production acquisition receives no version, export RVA or patch address arguments. The matrix covers the legacy `RBP` agent layout, lifted Win64 vtable calls, and both JDK attach JNI class names; these are resolution cases, not a supported-version whitelist.

The packed fixture is reproducible with `./gradlew :memshell-party-packer:windowsPackedFixtureJar`, which uses `FilelessAgentPacker.pack(MemShellResult)` and writes `memshell-party-packer/build/verification/windows-packed-fileless-fixture.jar`. Other Windows builds still require successful runtime PE, call-graph and JPLIS layout resolution. Windows OpenJ9 and non-x64 architectures remain unsupported.
