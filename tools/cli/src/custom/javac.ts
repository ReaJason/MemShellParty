/**
 * Thin wrapper around the local JDK's `javac` — `memparty custom build`
 * compiles the generated filter on the operator's machine, so a JDK (11+)
 * must be on PATH. The servlet API jar ships inside the package
 * (resources/) so compilation has no other dependency.
 */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** Locate the bundled javax.servlet-api jar (handles both src/ and dist/ layouts). */
export function servletApiJar(): string {
  const candidates = [
    new URL("../resources/javax.servlet-api-3.1.0.jar", import.meta.url), // dist/*.js
    new URL("../../resources/javax.servlet-api-3.1.0.jar", import.meta.url), // src/custom/*.ts
  ];
  for (const candidate of candidates) {
    const p = fileURLToPath(candidate);
    if (existsSync(p)) return p;
  }
  throw new Error(
    "bundled servlet-api jar not found (expected resources/javax.servlet-api-3.1.0.jar in the package)",
  );
}

/** Resolve javac or throw with an install hint. */
export function findJavac(): string {
  try {
    execFileSync("javac", ["-version"], { stdio: "pipe" });
    return "javac";
  } catch {
    throw new Error(
      "javac not found on PATH — 'memparty custom build' compiles Java locally, " +
        "install any JDK 11+ and retry",
    );
  }
}

/** True when a working javac is available (used to skip integration tests). */
export function hasJavac(): boolean {
  try {
    findJavac();
    return true;
  } catch {
    return false;
  }
}

export interface CompileOptions {
  /** Classpath entries (e.g. the servlet API jar for the filter). */
  classpath?: string[];
}

/**
 * Compile one or more .java files to Java 8 bytecode into `outDir`.
 * UTF-8 source encoding is forced (cover pages may carry CJK text).
 */
export function compileJava(sources: string[], outDir: string, opts: CompileOptions = {}): void {
  const javac = findJavac();
  const args = ["-encoding", "UTF-8", "--release", "8"];
  if (opts.classpath && opts.classpath.length > 0) {
    args.push("-cp", opts.classpath.join(process.platform === "win32" ? ";" : ":"));
  }
  args.push("-d", outDir, ...sources);
  execFileSync(javac, args, { stdio: "pipe" });
}
