// A strict unified-diff applier for the vendored-file tests (not a *.test.mjs). No fuzz and no offset search: every
// hunk's context and removed lines must sit exactly where its header says, after the earlier hunks of the same patch,
// or it throws. reverse = true un-applies the patch (its + lines are removed, its - lines restored).
export function applyPatch(text, patch, { reverse = false } = {}) {
  const lines = text.split('\n');
  const hunks = [];
  let cur = null;
  for (const raw of patch.split('\n')) {
    const h = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(raw);
    if (h) {
      cur = { oldStart: +h[1], newStart: +h[3], body: [] };
      hunks.push(cur);
    } else if (cur && /^[ +-]/.test(raw)) {
      cur.body.push(raw);
    } else if (cur && raw.startsWith('\\')) {
      throw new Error('patches must not touch the final newline');
    } else if (raw !== '' && !/^(---|\+\+\+|diff |index )/.test(raw) && cur) {
      throw new Error('unexpected patch line: ' + raw);
    }
  }
  if (!hunks.length) throw new Error('no hunks');
  const [del, add] = reverse ? ['+', '-'] : ['-', '+'];
  let delta = 0;
  for (const hunk of hunks) {
    const from = hunk.body.filter((l) => l[0] === ' ' || l[0] === del).map((l) => l.slice(1));
    const to = hunk.body.filter((l) => l[0] === ' ' || l[0] === add).map((l) => l.slice(1));
    const at = (reverse ? hunk.newStart : hunk.oldStart) - 1 + delta;
    for (let i = 0; i < from.length; i++) {
      if (lines[at + i] !== from[i]) throw new Error(`hunk @${at + 1} does not match at line ${at + i + 1}`);
    }
    lines.splice(at, from.length, ...to);
    delta += to.length - from.length;
  }
  return lines.join('\n');
}
