/**
 * Local-filesystem helpers for `memparty upload` / `memparty download`.
 *
 * Kept deliberately strict: a transfer command must fail loudly before it
 * touches the wire rather than clobber a local file or stream a directory.
 */
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

/** Max upload size: 64 MiB. Larger files belong in a real file manager. */
export const UPLOAD_SIZE_LIMIT = 64 * 1024 * 1024;

/**
 * Basename of a *remote* path. The remote host may be Windows or Linux, so
 * both `\` and `/` count as separators; trailing separators are stripped
 * first ("C:\\temp\\" -> "temp"). Returns "" when nothing usable remains.
 */
export function remoteBasename(remotePath: string): string {
  const trimmed = remotePath.replace(/[/\\]+$/, "");
  const parts = trimmed.split(/[/\\]/).filter((p) => p.length > 0);
  return parts.length > 0 ? parts[parts.length - 1]! : "";
}

/**
 * Decide where a download lands locally and refuse anything unsafe.
 *
 * - `localArg` omitted  -> ./<remote basename>
 * - `localArg` is an existing directory -> <dir>/<remote basename>
 * - otherwise `localArg` is the target file
 *
 * Throws when the name is unusable, the parent directory is missing, or the
 * target exists and `force` is not set (no silent overwrites).
 */
export function resolveDownloadPath(
  remotePath: string,
  localArg: string | undefined,
  force: boolean,
): string {
  const name = remoteBasename(remotePath);
  let target: string;
  if (localArg === undefined) {
    if (!name) {
      throw new Error(
        `cannot derive a local filename from remote path ${JSON.stringify(remotePath)} — pass -o`,
      );
    }
    target = name;
  } else if (existsSync(localArg) && statSync(localArg).isDirectory()) {
    if (!name) {
      throw new Error(
        `cannot derive a local filename from remote path ${JSON.stringify(remotePath)} — pass -o with a file path`,
      );
    }
    target = join(localArg, name);
  } else {
    target = localArg;
  }

  const abs = resolve(target);
  if (existsSync(abs)) {
    if (statSync(abs).isDirectory()) {
      throw new Error(`local path ${target} is a directory — pass -o with a file path`);
    }
    if (!force) {
      throw new Error(`local file ${target} already exists — pass --force to overwrite`);
    }
  }
  const parent = dirname(abs);
  if (!existsSync(parent) || !statSync(parent).isDirectory()) {
    throw new Error(`local directory ${parent} does not exist`);
  }
  return abs;
}

/**
 * Read a local file for upload. Throws unless it is a regular file within
 * the size limit — directories, devices and missing files are all errors,
 * never silent empty uploads.
 */
export function readUploadFile(localPath: string, maxBytes = UPLOAD_SIZE_LIMIT): Buffer {
  if (!existsSync(localPath)) {
    throw new Error(`local file ${localPath} does not exist`);
  }
  const stat = statSync(localPath);
  if (!stat.isFile()) {
    throw new Error(`local path ${localPath} is not a regular file`);
  }
  if (stat.size > maxBytes) {
    throw new Error(
      `local file ${localPath} is ${stat.size} bytes — over the ${maxBytes}-byte upload limit`,
    );
  }
  return readFileSync(localPath);
}
