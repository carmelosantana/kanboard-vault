"""The export gate's readers (spec: KeePassXC import and export -> CI gate, step 4): pykeepass and keepassxc-cli must
both open Vault's export and find every entry with an identical title, username, password, URL, notes and custom
fields (and the same protection, tags and expiry, and every group).

Run inside the throwaway container from Dockerfile (R3), with no network, as
    python3 -I verify.py <work dir>
where the work dir holds export.kdbx, export-password (the export password, one line) and expected.json (written by
gate.mjs from gate-fixtures.mjs). Readers:
    pykeepass       opens the file and reads every group and entry;
    keepassxc-cli   `export -f xml` (KeePassXC's own reader, every entry), `ls -R -f` (every group and entry path),
                    and `show -s -a ...` for every entry outside the 10,000 bulk ones plus every 250th of those,
                    whose output must be exactly each attribute's value and a newline.
Protection is compared for non-empty values only (an empty value has nothing to protect). Prints one line per check
and `verify: PASS` or `verify: FAIL (n)`; exits 0 only on PASS.
"""
import json
import subprocess
import sys
import base64
from datetime import datetime, timedelta, timezone

from lxml import etree
from pykeepass import PyKeePass

STANDARD = ['Title', 'UserName', 'Password', 'URL', 'Notes']
failures = 0


def check(ok, what):
    global failures
    print(('PASS ' if ok else 'FAIL ') + what, flush=True)
    if not ok:
        failures += 1


def norm(entry):
    """An entry for comparison: protection kept only for non-empty values."""
    return {
        'path': list(entry['path']),
        'fields': {k: [v[0], bool(v[1]) if v[0] != '' else None] for k, v in entry['fields'].items()},
        'tags': list(entry['tags']),
        'expires': entry['expires'],
    }


def key(entry):
    return json.dumps([entry['path'], entry['fields'].get('Title', [''])[0]], ensure_ascii=False)


def compare(reader, got, want):
    got_n = sorted((norm(e) for e in got), key=key)
    want_n = sorted((norm(e) for e in want), key=key)
    check(len(got_n) == len(want_n), f'{reader}: {len(got_n)} entries (want {len(want_n)})')
    diffs = [(g, w) for g, w in zip(got_n, want_n) if g != w]
    for g, w in diffs[:3]:
        print('  got: ' + json.dumps(g, ensure_ascii=False)[:600])
        print('  want: ' + json.dumps(w, ensure_ascii=False)[:600])
    check(not diffs and len(got_n) == len(want_n), f'{reader}: every entry identical, field for field ({len(diffs)} differ)')


def iso(dt):
    return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def kdbx_time(text):
    """A KeePass XML time: ISO text (KDBX 3) or base64 of the seconds since 0001-01-01 as a little-endian int64 (KDBX 4)."""
    if 'T' in text:
        return datetime.strptime(text, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    seconds = int.from_bytes(base64.b64decode(text), 'little')
    return iso(datetime(1, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds))


def read_pykeepass(path, password):
    kp = PyKeePass(path, password=password)
    entries = []
    for e in kp.entries:
        fields = {}
        for s in e._element.findall('String'):
            value = s.find('Value')
            fields[s.find('Key').text] = [value.text or '', value.get('Protected') == 'True']
        entries.append({
            'path': list(e.group.path),
            'fields': fields,
            'tags': list(e.tags),
            'expires': iso(e.expiry_time) if e.expires else None,
        })
    groups = [list(g.path) for g in kp.groups if g.path]
    return groups, entries


def kpxc(args, password):
    r = subprocess.run(['keepassxc-cli', *args], input=(password + '\n').encode(), capture_output=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(f'keepassxc-cli {args[0]} failed ({r.returncode}): {r.stderr.decode(errors="replace")[:300]}')
    return r.stdout.decode('utf-8')


def read_kpxc_xml(path, password):
    # KeePassXC writes a CR in a value as a literal CR, which an XML parser would turn into LF: keep it as &#13;.
    xml = kpxc(['export', '-q', '-f', 'xml', path], password).encode('utf-8').replace(b'\r', b'&#13;')
    root = etree.fromstring(xml)
    groups, entries = [], []

    def walk(group, gpath):
        for e in group.findall('Entry'):
            fields = {}
            for s in e.findall('String'):
                value = s.find('Value')
                fields[s.find('Key').text] = [value.text or '', value.get('ProtectInMemory') == 'True']
            tags = e.findtext('Tags') or ''
            times = e.find('Times')
            expires = times.findtext('Expires') == 'True'
            entries.append({
                'path': gpath,
                'fields': fields,
                'tags': [t.strip() for t in tags.replace(';', ',').split(',') if t.strip()],
                'expires': kdbx_time(times.findtext('ExpiryTime')) if expires else None,
            })
        for sub in group.findall('Group'):
            p = gpath + [sub.findtext('Name') or '']
            groups.append(p)
            walk(sub, p)

    walk(root.find('Root/Group'), [])
    return groups, entries


def main():
    work = sys.argv[1]
    db = work + '/export.kdbx'
    with open(work + '/export-password', encoding='utf-8') as f:
        password = f.read().rstrip('\n')
    with open(work + '/expected.json', encoding='utf-8') as f:
        want = json.load(f)
    want_groups = sorted(json.dumps(g, ensure_ascii=False) for g in want['groups'])

    groups, entries = read_pykeepass(db, password)
    check(sorted(json.dumps(g, ensure_ascii=False) for g in groups) == want_groups, f'pykeepass: every group ({len(groups)})')
    compare('pykeepass', entries, want['entries'])

    info = kpxc(['db-info', '-q', db], password)
    check('Cipher: ChaCha20 256-bit' in info and 'KDF: Argon2id' in info, 'keepassxc-cli db-info: ' + ' / '.join(l for l in info.splitlines() if l.startswith(('Cipher', 'KDF'))))
    groups, entries = read_kpxc_xml(db, password)
    check(sorted(json.dumps(g, ensure_ascii=False) for g in groups) == want_groups, f'keepassxc-cli export: every group ({len(groups)})')
    compare('keepassxc-cli export', entries, want['entries'])

    listed = sorted(l for l in kpxc(['ls', '-q', '-R', '-f', db], password).splitlines() if l != '')
    want_listed = sorted(['/'.join(g) + '/' for g in want['groups']] + ['/'.join(e['path'] + [e['fields']['Title'][0]]) for e in want['entries']])
    check(listed == want_listed, f'keepassxc-cli ls -R -f: every group and entry path ({len(listed)} lines)')

    bulk = [e for e in want['entries'] if e['path'][0] == 'Bulk']
    sample = [e for e in want['entries'] if e['path'][0] != 'Bulk'] + bulk[::250]
    bad = 0
    for e in sample:
        attrs = STANDARD + [k for k in e['fields'] if k not in STANDARD]
        args = ['show', '-q', '-s']
        for a in attrs:
            args += ['-a', a]
        out = kpxc(args + [db, '/'.join(e['path'] + [e['fields']['Title'][0]])], password)
        if out != ''.join(e['fields'][a][0] + '\n' for a in attrs):
            bad += 1
            if bad <= 3:
                print('  show ' + '/'.join(e['path'] + [e['fields']['Title'][0]]) + ': ' + json.dumps(out, ensure_ascii=False)[:400])
    check(bad == 0, f'keepassxc-cli show -s: {len(sample)} entries, every attribute exact ({bad} differ)')

    print('verify: PASS' if failures == 0 else f'verify: FAIL ({failures})')
    sys.exit(0 if failures == 0 else 1)


if __name__ == '__main__':
    main()
