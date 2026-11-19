<?php

namespace Kanboard\Plugin\Vault\WebAuthn;

/**
 * A fail-closed CBOR (RFC 8949) decoder for WebAuthn (spec: Hardware keys, the CBOR rule list). It rejects
 * indefinite lengths, tags, floats, simple values other than false/true/null, duplicate map keys, integers
 * and lengths that aren't minimally encoded, invalid UTF-8, trailing bytes, more than 4 nested containers,
 * more than 64 data items in total, more than 4096 bytes of input, and any value past PHP_INT_MAX/MIN.
 *
 * Types out: unsigned/negative int -> int, byte string -> CborBytes, text -> string, array -> CborArray,
 * map -> PHP array, false/true/null -> bool/null. Map keys must be ints or text; a text key PHP would turn
 * into an int (e.g. "1") is refused, so a text label can never alias a COSE int label.
 */
final class Cbor
{
    public const MAX_BYTES = 4096;
    public const MAX_DEPTH = 4;
    public const MAX_ITEMS = 64;

    private int $pos = 0;
    private int $items = 0;

    private function __construct(private readonly string $in)
    {
    }

    // Decodes exactly one item that spans the whole input.
    public static function decode(string $bytes): mixed
    {
        [$value, $used] = self::decodePrefix($bytes);
        if ($used !== strlen($bytes)) {
            throw new CborException('cbor_invalid');
        }
        return $value;
    }

    // Decodes the first item of the input, under the same rules; returns it and the bytes it used.
    // authData embeds the COSE key and the extensions map back to back, so their ends are found this way.
    /** @return array{0:mixed, 1:int} */
    public static function decodePrefix(string $bytes): array
    {
        if ($bytes === '' || strlen($bytes) > self::MAX_BYTES) {
            throw new CborException('cbor_invalid');
        }
        $d = new self($bytes);
        $value = $d->item(0);
        return [$value, $d->pos];
    }

    private function take(int $n): string
    {
        if ($n < 0 || $n > strlen($this->in) - $this->pos) {
            throw new CborException('cbor_invalid');
        }
        $s = substr($this->in, $this->pos, $n);
        $this->pos += $n;
        return $s;
    }

    // The argument of a head: minimal encoding enforced, no indefinite or reserved forms, no value past PHP_INT_MAX.
    private function argument(int $info): int
    {
        if ($info < 24) {
            return $info;
        }
        [$n, $min] = match ($info) {
            24 => [ord($this->take(1)), 24],
            25 => [unpack('n', $this->take(2))[1], 0x100],
            26 => [unpack('N', $this->take(4))[1], 0x10000],
            27 => [unpack('J', $this->take(8))[1], 0x100000000],
            default => throw new CborException('cbor_invalid'), // 28-30 reserved, 31 indefinite
        };
        if ($n < $min) { // not minimal; for 27 a negative $n means the uint64 overflowed PHP_INT_MAX
            throw new CborException('cbor_invalid');
        }
        return $n;
    }

    // Reserves $n more data items against the total budget before anything is read for them.
    private function count(int $n): void
    {
        if ($n > self::MAX_ITEMS - $this->items) {
            throw new CborException('cbor_invalid');
        }
        $this->items += $n;
    }

    private function item(int $depth): mixed
    {
        $this->count(1);
        $head = ord($this->take(1));
        $major = $head >> 5;
        $info = $head & 0x1f;

        if ($major === 7) {
            return match ($info) {
                20 => false,
                21 => true,
                22 => null,
                default => throw new CborException('cbor_invalid'), // undefined, simple(n), floats, break
            };
        }
        if ($major === 6) {
            throw new CborException('cbor_invalid'); // tags
        }

        $arg = $this->argument($info);
        switch ($major) {
            case 0:
                return $arg;
            case 1:
                return -1 - $arg; // $arg <= PHP_INT_MAX, so the result is >= PHP_INT_MIN
            case 2:
                return new CborBytes($this->take($arg));
            case 3:
                $s = $this->take($arg);
                if (preg_match('//u', $s) !== 1) {
                    throw new CborException('cbor_invalid');
                }
                return $s;
            case 4:
                if ($depth + 1 > self::MAX_DEPTH) {
                    throw new CborException('cbor_invalid');
                }
                $list = [];
                for ($i = 0; $i < $arg; $i++) {
                    $list[] = $this->item($depth + 1);
                }
                return new CborArray($list);
            default: // 5, map
                if ($depth + 1 > self::MAX_DEPTH) {
                    throw new CborException('cbor_invalid');
                }
                $map = [];
                for ($i = 0; $i < $arg; $i++) {
                    $key = $this->item($depth + 1);
                    if (! is_int($key) && ! is_string($key)) {
                        throw new CborException('cbor_invalid');
                    }
                    if (is_string($key) && ! is_string(array_key_first([$key => true]))) {
                        throw new CborException('cbor_invalid'); // PHP would turn this text key into an int
                    }
                    if (array_key_exists($key, $map)) {
                        throw new CborException('cbor_invalid');
                    }
                    $map[$key] = $this->item($depth + 1);
                }
                return $map;
        }
    }
}
