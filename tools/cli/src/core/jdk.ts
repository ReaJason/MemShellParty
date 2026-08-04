/** Maps friendly JDK names to Java class-file major versions. */
export const JDK_VERSIONS: Record<string, number> = {
  java6: 50,
  java8: 52,
  java9: 53,
  java11: 55,
  java17: 61,
  java21: 65,
};

/**
 * Resolve a user-supplied JDK value into a class-file major version number.
 * Accepts friendly names ("java8", "8"), or a raw major version ("52").
 */
export function resolveJreVersion(input: string | number | undefined): number | undefined {
  if (input === undefined || input === "") return undefined;

  if (typeof input === "number") return input;

  const normalized = input.trim().toLowerCase();

  // Friendly name, e.g. "java8"
  if (normalized in JDK_VERSIONS) return JDK_VERSIONS[normalized];

  // Bare java number, e.g. "8" -> java8
  const withPrefix = `java${normalized}`;
  if (withPrefix in JDK_VERSIONS) return JDK_VERSIONS[withPrefix];

  // Raw class-file major version, e.g. "52"
  const num = Number(normalized);
  if (Number.isInteger(num) && num > 0) return num;

  throw new Error(
    `Invalid JDK version "${input}". Use one of: ${Object.keys(JDK_VERSIONS).join(", ")}, or a class-file major version like 52.`,
  );
}
