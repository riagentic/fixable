// The format of a Fixable drop-in, and the arithmetic on it. Pure text.
//
// A hundred kernel-parameter checks all want a line in the same file, and each
// of them has its own button. So a check does not describe a file — it
// describes ONE contribution to one, tagged with the check's id:
//
//     # Managed by Fixable — one block per check. Delete a block to undo it.
//
//     # fixable:sysctl-protected-regular
//     fs.protected_regular = 2
//
//     # fixable:sysctl-syncookies
//     net.ipv4.tcp_syncookies = 1
//
// The marker goes on its own line above the setting, never after it: every
// format this app writes into (sysctl.d, modprobe.d, limits.d, sshd_config.d,
// systemd .conf.d) treats a whole line starting `#` as a comment, and none of
// them reliably strips a trailing one. A value with a comment glued to the end
// of it is how a "safe" write corrupts a setting.
//
// Because each block is labelled, three things fall out for free: applying a
// check twice replaces its block instead of duplicating it, undoing one check
// removes its block and leaves everybody else's, and undoing the last one
// leaves a file with no blocks — which the caller deletes rather than leaving
// an empty file the system still has to parse.

export const DROPIN_HEADER =
  "# Managed by Fixable — one block per check. Delete a block to undo it.";

const MARKER = /^#\s*fixable:([a-z0-9][a-z0-9-]*)\s*$/;

/** Read a drop-in back into the blocks that built it.
 *
 *  Anything outside a marked block — a header, a stray edit, a line somebody
 *  added by hand — is not represented, and so is dropped when the file is
 *  rendered again. That is safe only because these files are Fixable's own and
 *  nothing else is supposed to be in them; it is exactly why the app writes to
 *  `99-fixable.conf` and never to a file the distribution ships. */
export const parseDropIn = (text: string | null): Map<string, string> => {
  const blocks = new Map<string, string>();
  let id: string | null = null;
  let lines: string[] = [];
  const flush = () => {
    if (id !== null) blocks.set(id, lines.join("\n").trim());
    id = null;
    lines = [];
  };
  for (const line of (text ?? "").split("\n")) {
    const m = MARKER.exec(line);
    if (m) {
      flush();
      id = m[1]!;
    } else if (id !== null) lines.push(line);
  }
  flush();
  // A marker with nothing under it says nothing and would render as an empty
  // block forever. Treat it as absent.
  for (const [k, v] of blocks) if (v === "") blocks.delete(k);
  return blocks;
};

/** Render blocks back to a file. Sorted by id, so the same set of applied
 *  checks always produces byte-identical contents — a file that reshuffles
 *  itself on every write is a file nobody can diff. */
export const renderDropIn = (blocks: Map<string, string>): string => {
  const ids = [...blocks.keys()].sort();
  if (ids.length === 0) return "";
  return [
    DROPIN_HEADER,
    "",
    ...ids.flatMap((id) => [`# fixable:${id}`, blocks.get(id)!, ""]),
  ].join("\n");
};

/** Apply one check's contribution. `text === null` removes the block, which is
 *  what undo is. Returns a new map — the caller's is untouched. */
export const withBlock = (
  blocks: Map<string, string>,
  id: string,
  text: string | null,
): Map<string, string> => {
  const next = new Map(blocks);
  if (text === null) next.delete(id);
  else next.set(id, text.trim());
  return next;
};
