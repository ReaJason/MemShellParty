/**
 * Library entrypoint — re-exports the reusable API client, types, and
 * request/output helpers so this package can be consumed programmatically,
 * not only as a CLI.
 */
export * from "./api/index.js";
export {
  buildMemShellRequest,
  buildProbeRequest,
  type MemShellOptions,
  type ProbeOptions,
} from "./core/request-builder.js";
export { emitPayload, shouldDecode, type OutputOptions, type OutputResult } from "./core/output.js";
export { resolveApiUrl, DEFAULT_API_URL, ENV_VAR } from "./core/config.js";
export { resolveJreVersion, JDK_VERSIONS } from "./core/jdk.js";
export {
  formatOp,
  logOp,
  opLogPath,
  readOps,
  truncateOutput,
  OUTPUT_LIMIT,
  type OpCategory,
  type OpFilter,
  type OpLogEntry,
} from "./core/oplog.js";
export { createMcpServer, startMcpStdio } from "./mcp/server.js";
export {
  autoSaveShell,
  getProject,
  listProjects,
  removeProject,
  removeShell,
  resolveConnection,
  saveProjectMeta,
  saveShell,
  saveShellMeta,
  targetStorePath,
  type ConnectionFlags,
  type ResolvedConnection,
  type ShellInput,
  type StoredProject,
  type StoredShell,
} from "./core/targets.js";
export { execBehinder, testBehinder, type BehinderConnectOptions } from "./connect/behinder.js";
export { execGodzilla, testGodzilla, type GodzillaExecOptions } from "./connect/godzilla.js";
export {
  LEGACY_CIPHER,
  deriveMarkers,
  resolveCipher,
  type MimicCipher,
} from "./connect/mimic-codecs.js";
export {
  buildCustomMemshell,
  defaultClassName,
  profileSecretFields,
  type BuildDeps,
  type CustomBuildInput,
  type CustomBuildResult,
  type GenerateClient,
} from "./custom/build.js";
export { renderCryptoProbe, renderFilterJava, type FilterTemplateOptions } from "./custom/java-template.js";
export { hasJavac } from "./custom/javac.js";
export {
  installSkill,
  skillSourceDir,
  skillTargetDir,
  SKILL_NAME,
  type InstallSkillOptions,
  type SkillInstallResult,
  type SkillScope,
} from "./core/skill-install.js";
export {
  testSuo5,
  marshalSuo5Map,
  unmarshalSuo5Map,
  marshalFrameBase64,
  unmarshalFrameBase64,
  type Suo5ConnectOptions,
  type Suo5Mode,
} from "./connect/suo5.js";
export type {
  CommonConnectOptions,
  ConnectTestResult,
  ConnectTool,
  ExecResult,
} from "./connect/types.js";
export { CLI_VERSION } from "./version.js";
