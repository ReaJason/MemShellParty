/**
 * Whether a response probe reads a value from the request parameter/header.
 * Keep the form, submitted payload and generated result aligned with ResponseGenerator.
 */
export function usesRequestParam(probeContent?: string, server?: string): boolean {
  return (
    probeContent === "Command" ||
    probeContent === "Bytecode" ||
    probeContent === "ScriptEngine" ||
    // UnknownWriter uses the value to claim the live request during its object-graph scan.
    (probeContent === "Server" && server === "Unknown")
  );
}
