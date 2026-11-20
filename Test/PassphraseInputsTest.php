<?php
use PHPUnit\Framework\TestCase;

// Ruling R70 (T24 fix round 1, carry 4: no browser "save password" prompt for anything Vault asks for). Every input in
// a Vault template that takes a passphrase or password (the vault passphrase for unlock, enrolment, passphrase change,
// rotation, recovery, re-auth and hardware keys; the recovery code; the export and import passwords; the one-time
// share passphrase; an entry's password) carries autocomplete="off" and the password-manager ignore hints
// data-1p-ignore, data-lpignore="true" and data-bwignore. The inputs are found, not listed: any <input> of type
// password, or with a data-* attribute named for a pass(word|phrase), or an id or name naming one (or the recovery
// code); checkboxes, radios and hidden fields excepted. Kills: a new passphrase input added without the rule;
// current-password or new-password back on any of them; a hint dropped.
class PassphraseInputsTest extends TestCase
{
    /** @return list<array{where:string, tag:string}> */
    private static function passphraseInputs(): array
    {
        $out = [];
        $root = realpath(__DIR__.'/../Template');
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $file) {
            if ($file->getExtension() !== 'php') {
                continue;
            }
            // Embedded PHP blocks are replaced first, so a tag ends at its own closing bracket.
            $src = preg_replace('/<\?(php|=).*?\?'.'>/s', 'PHP', (string) file_get_contents($file->getPathname()));
            preg_match_all('/<input\b[^>]*>/is', $src, $m);
            foreach ($m[0] as $tag) {
                $tag = preg_replace('/\s+/', ' ', $tag);
                $type = preg_match('/\btype="([^"]*)"/i', $tag, $t) ? strtolower($t[1]) : 'text';
                if (in_array($type, ['checkbox', 'radio', 'hidden'], true)) {
                    continue;
                }
                preg_match_all('/\s([a-z0-9-]+)(?:="([^"]*)")?/i', $tag, $attrs, PREG_SET_ORDER);
                $named = false;
                foreach ($attrs as $a) {
                    $name = strtolower($a[1]);
                    $value = strtolower($a[2] ?? '');
                    if ((str_starts_with($name, 'data-') && str_contains($name, 'pass'))
                        || (in_array($name, ['id', 'name'], true) && preg_match('/pass|recovery-code/', $value))) {
                        $named = true;
                    }
                }
                if ($type === 'password' || $named) {
                    $id = preg_match('/\bid="([^"]*)"/', $tag, $i) ? $i[1] : $tag;
                    $out[] = ['where' => substr($file->getPathname(), strlen($root) + 1).'#'.$id, 'tag' => $tag];
                }
            }
        }
        return $out;
    }

    public function testEveryPassphraseInputRefusesBrowserSaving(): void
    {
        $inputs = self::passphraseInputs();
        $where = array_column($inputs, 'where');
        // The scan must see the inputs R70 names, so a broken scan can't pass vacuously.
        foreach (['vault/locked.php#vault-passphrase', 'vault/locked.php#vault-recovery-code', 'vault/enrol.php#vault-new-passphrase',
            'vault/security.php#vault-current', 'vault/security.php#vault-rotate-passphrase', 'vault/security.php#vault-recovery-passphrase',
            'vault/export.php#vault-export-passphrase', 'vault/export.php#vault-new-passphrase', 'vault/hwkeys.php#vault-hw-passphrase',
            'vault/onetime_dialog.php#vault-ot-pass', 'share/show.php#vault-reveal-passphrase', 'vault/import.php#vault-import-password',
            'vault/edit.php#vault-e-password'] as $want) {
            $this->assertContains($want, $where, "the scan finds $want");
        }
        $this->assertGreaterThanOrEqual(20, count($inputs));
        $bad = [];
        foreach ($inputs as $input) {
            $tag = $input['tag'];
            $ok = preg_match('/\sautocomplete="off"/', $tag) && preg_match('/\sdata-1p-ignore(?=[\s>=\/])/', $tag)
                && preg_match('/\sdata-lpignore="true"/', $tag) && preg_match('/\sdata-bwignore(?=[\s>=\/])/', $tag);
            if (! $ok) {
                $bad[] = $input['where'];
            }
        }
        $this->assertSame([], $bad, 'passphrase inputs without autocomplete="off" and the 1p/lp/bw ignore hints');
    }
}
