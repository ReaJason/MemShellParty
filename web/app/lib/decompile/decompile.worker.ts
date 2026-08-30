import "./prism-worker-guard";
import { decompile } from "@run-slicer/cfr";
import Prism from "prismjs";
import "prismjs/components/prism-clike";
import "prismjs/components/prism-java";

/** [tokenType, text] segments of one rendered line */
export type TokenLine = Array<[string, string]>;

export interface DecompiledClass {
  source: string;
  lines: TokenLine[];
}

export interface DecompileRequest {
  id: number;
  shellClassName: string;
  shellBytesBase64: string;
  injectorClassName?: string;
  injectorBytesBase64?: string;
}

export interface DecompileResponse {
  id: number;
  shell?: DecompiledClass;
  injector?: DecompiledClass;
  error?: string;
}

function base64ToBytes(base64String: string) {
  const byteCharacters = atob(base64String);
  const bytes = new Uint8Array(byteCharacters.length);
  for (let i = 0; i < byteCharacters.length; i++) {
    bytes[i] = byteCharacters.charCodeAt(i);
  }
  return bytes;
}

function toJvmClassName(className: string) {
  return className.replaceAll(".", "/");
}

function tokenizeToLines(code: string): TokenLine[] {
  const lines: TokenLine[] = [[]];
  const push = (type: string, text: string) => {
    const parts = text.split("\n");
    for (let i = 0; i < parts.length; i++) {
      if (i > 0) lines.push([]);
      if (parts[i]) lines[lines.length - 1].push([type, parts[i]]);
    }
  };
  const walk = (token: string | Prism.Token, inheritedType: string) => {
    if (typeof token === "string") {
      push(inheritedType, token);
      return;
    }
    const { type, content } = token;
    if (typeof content === "string") {
      push(type, content);
      return;
    }
    for (const child of Array.isArray(content) ? content : [content]) {
      walk(child, type);
    }
  };
  for (const token of Prism.tokenize(code, Prism.languages.java)) {
    walk(token, "plain");
  }
  return lines;
}

/** CFR options: no "Could not load the following classes" list, no version banner */
const CFR_OPTIONS = { comments: "false", showversion: "false" };

/** Strip CFR's leading "Decompiled with CFR" banner comment */
function stripCfrBanner(source: string): string {
  return source.replace(/^\/\*\r?\n \* Decompiled with CFR[\s\S]*?\*\/\r?\n?/, "");
}

async function decompileClass(
  jvmClassName: string,
  classes: Map<string, Uint8Array>,
): Promise<DecompiledClass> {
  const raw = await decompile(jvmClassName, {
    source: (name) => classes.get(name) ?? null,
    options: CFR_OPTIONS,
  });
  const source = stripCfrBanner(raw);
  return { source, lines: tokenizeToLines(source) };
}

self.onmessage = async (event: MessageEvent<DecompileRequest>) => {
  const { id, shellClassName, shellBytesBase64, injectorClassName, injectorBytesBase64 } =
    event.data;
  try {
    const classes = new Map<string, Uint8Array>([
      [toJvmClassName(shellClassName), base64ToBytes(shellBytesBase64)],
    ]);
    const hasInjector = injectorClassName && injectorBytesBase64;
    if (hasInjector) {
      classes.set(toJvmClassName(injectorClassName), base64ToBytes(injectorBytesBase64));
    }
    const shell = await decompileClass(toJvmClassName(shellClassName), classes);
    const injector = hasInjector
      ? await decompileClass(toJvmClassName(injectorClassName), classes)
      : undefined;
    self.postMessage({ id, shell, injector } satisfies DecompileResponse);
  } catch (error) {
    self.postMessage({
      id,
      error: error instanceof Error ? error.message : String(error),
    } satisfies DecompileResponse);
  }
};
