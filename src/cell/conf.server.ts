// Writing a user configuration file, safely.
//
// Three properties, and the whole family of config checks rests on them:
//
//   1. Atomic — the new contents land by rename, so a crash mid-write leaves
//      the old file intact rather than half a file.
//   2. Exactly undoable — the previous contents are captured verbatim,
//      including "there was no file", and Undo restores that state.
//   3. Never clobbers — Undo refuses if the file no longer holds what the fix
//      wrote. Silently overwriting someone's later edit would be precisely the
//      harm this app exists to avoid.
import { dirname } from "@std/path";
import { absent, readText } from "./sys.server.ts";

export type ConfWrite = {
  path: string;
  /** The file's contents before the fix, or null when it did not exist. */
  before: string | null;
  /** What the fix wrote — the fingerprint Undo checks against. */
  wrote: string;
};

/** Does the parent directory exist?
 *
 *  A config policy may create its file, but never its directory tree: making
 *  `~/.gnupg` (and getting its mode right) is the tool's job, not ours. No
 *  parent means the check does not apply to this machine. */
export async function parentExists(path: string): Promise<boolean> {
  try {
    return (await Deno.stat(dirname(path))).isDirectory;
  } catch {
    return false;
  }
}

/** lstat, or null when nothing is there. */
async function lstatOf(path: string): Promise<Deno.FileInfo | null> {
  try {
    return await Deno.lstat(path);
  } catch (e) {
    if (absent(e)) return null;
    throw e;
  }
}

/** Is `path` a symlink? A rename would replace the link itself with a plain
 *  file — the dotfiles repo it pointed into silently stops being used — so a
 *  linked config is reported, never rewritten. */
export const isSymlink = async (path: string): Promise<boolean> =>
  (await lstatOf(path))?.isSymlink ?? false;

/** The contents of a regular file this module may replace, or null when there
 *  is none. Refuses anything else, before a byte is written. */
async function readOwn(
  path: string,
): Promise<{ text: string | null; mode: number }> {
  const st = await lstatOf(path);
  if (st === null) {
    // A new config file is private by default: these hold tokens often
    // enough that 0644 would be its own finding two rows down this list.
    return { text: null, mode: 0o600 };
  }
  if (st.isSymlink) {
    throw new Error(
      `${path} is a symlink — refusing to replace it with a plain file; ` +
        `edit the file it points to by hand`,
    );
  }
  if (!st.isFile) throw new Error(`${path} is not a regular file`);
  // Strict UTF-8 (readText): a lossy decode would corrupt `before`, and Undo
  // would then "restore" damage.
  return { text: await readText(path), mode: (st.mode ?? 0o600) & 0o7777 };
}

/** Replace a file's contents atomically and durably, preserving its mode.
 *
 *  The temp file is created exclusively, with the final mode from the first
 *  byte (never readable under a looser umask, even for a moment), flushed to
 *  disk before the rename — otherwise a power cut can leave the renamed file
 *  empty — and removed on any failure. */
export async function writeConf(
  path: string,
  next: string,
): Promise<ConfWrite> {
  const { text: before, mode } = await readOwn(path);
  const tmp = `${path}.fixable-${Deno.pid}-${
    crypto.randomUUID().slice(0, 8)
  }.tmp`;
  const f = await Deno.open(tmp, { write: true, createNew: true, mode });
  try {
    try {
      const data = new TextEncoder().encode(next);
      for (let off = 0; off < data.length;) {
        off += await f.write(data.subarray(off));
      }
      // `mode` at open is filtered by the umask; chmod makes it exact.
      await Deno.chmod(tmp, mode);
      await f.syncData();
    } finally {
      f.close();
    }
    await Deno.rename(tmp, path);
  } catch (e) {
    await Deno.remove(tmp).catch(() => {});
    throw e;
  }
  await syncDir(dirname(path));
  return { path, before, wrote: next };
}

/** Persist the rename itself. Best effort: the file is already correct, and
 *  a filesystem that cannot fsync a directory is not a reason to fail. */
async function syncDir(dir: string): Promise<void> {
  try {
    const d = await Deno.open(dir, { read: true });
    try {
      await d.sync();
    } finally {
      d.close();
    }
  } catch { /* not supported here */ }
}

/** Put back exactly what was there — or, if the file has moved on, put back
 *  only the part this fix changed.
 *
 *  The whole-file restore is the exact one and is used whenever it is still
 *  correct. It stops being correct as soon as anything else edits the file —
 *  including the NEXT fix, since a dozen rows can share one `gpg.conf`. Undoing
 *  the first of them would then either refuse (leaving you no way back) or
 *  overwrite the other eleven. Neither is acceptable, so a `narrow` fallback
 *  reverts one key and leaves every other line alone. */
export const restoreConf = (
  w: ConfWrite,
  narrow?: (text: string) => string,
) =>
async (): Promise<void> => {
  const { text: current } = await readOwn(w.path);
  if (current === w.wrote) {
    if (w.before === null) await Deno.remove(w.path);
    else await writeConf(w.path, w.before);
    return;
  }
  if (current !== null && narrow) {
    await writeConf(w.path, narrow(current));
    return;
  }
  throw new Error(
    `${w.path} has changed since the fix, and this change cannot be undone ` +
      `on its own — edit the file by hand`,
  );
};
