import type { MemShellFormSchema } from "@/types/schema";

import assert from "node:assert/strict";
import { test } from "node:test";

import { restoreMemShellFormValues, transformToPostData } from "@/utils/transformer";

function memShellValues(overrides: Partial<MemShellFormSchema> = {}): MemShellFormSchema {
  return {
    server: "Tomcat",
    serverVersion: "Unknown",
    shellTool: "Godzilla",
    shellType: "Listener",
    packingMethod: "DefaultBase64",
    ...overrides,
  };
}

test("memshell transformation defaults a missing obfuscation scope to ALL", () => {
  const { shellConfig } = transformToPostData(memShellValues());

  assert.equal(shellConfig.obfuscationScope, "ALL");
  assert.deepEqual(shellConfig.obfuscation, { enabled: false });
});

test("memshell transformation keeps the selected scope beside obfuscation", () => {
  const { shellConfig } = transformToPostData(
    memShellValues({ obfuscation: true, obfuscationScope: "INJECTOR" }),
  );

  assert.equal(shellConfig.obfuscationScope, "INJECTOR");
  assert.deepEqual(shellConfig.obfuscation, { enabled: true, options: {} });
});

test("disabling obfuscation does not enable it through scope selection", () => {
  const { shellConfig } = transformToPostData(
    memShellValues({ obfuscation: false, obfuscationScope: "MEMSHELL" }),
  );

  assert.equal(shellConfig.obfuscationScope, "MEMSHELL");
  assert.deepEqual(shellConfig.obfuscation, { enabled: false });
});

test("history restore defaults only a missing scope and preserves existing values", () => {
  const historical = memShellValues({ shellClassName: "example.Shell" });
  const restored = restoreMemShellFormValues(historical);

  assert.equal(restored.obfuscationScope, "ALL");
  assert.equal(restored.shellClassName, "example.Shell");
  assert.equal(historical.obfuscationScope, undefined);

  assert.equal(
    restoreMemShellFormValues(memShellValues({ obfuscationScope: "MEMSHELL" })).obfuscationScope,
    "MEMSHELL",
  );
});
