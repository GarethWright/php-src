<div align="center">
    <a href="https://www.php.net">
        <img
            alt="PHP"
            src="https://www.php.net/images/logos/new-php-logo.svg"
            width="150">
    </a>
</div>

# PHP Source Inspector

> **This is a modified PHP binary.**  
> For the upstream PHP interpreter, see [php/php-src](https://github.com/php/php-src).

This fork adds a source/bytecode inspector that dumps the PHP source — or
decoded opcode listing — of **every file the interpreter executes**.
Output goes to per-script files in a configurable directory
(`inspector.output_dir`), making the binary a transparent drop-in, or to
stderr when no directory is set. It is designed for reverse-engineering PHP
applications, particularly those protected by commercial loaders (IonCube,
Zend Guard, SourceGuardian, etc.) or OPcache file-cache-only deployments
where no `.php` source files are present.

[![Build Release](https://github.com/GarethWright/php-src/actions/workflows/release.yml/badge.svg)](https://github.com/GarethWright/php-src/actions/workflows/release.yml)

## How it works

Three hook points together cover every code path:

| Hook | What it catches |
|------|----------------|
| `zend_compile_file` | Normal `require`/`include`/autoload without OPcache |
| `zend_accel_load_script` (OPcache internals) | **Every** OPcache path: SHM cache hits, file-cache hits (`file_cache_only=1`), newly compiled scripts, preloaded scripts |
| `zend_compile_string` | `eval()`, `assert(string)`, runtime-decrypted payloads |

For each compiled unit the inspector decides what to output:

```
Source file readable on disk?
  YES → /* ===[ PHP SOURCE: filename ]=== */
        <verbatim source>
        /* ===[ END SOURCE: filename ]=== */

  NO  → /* ===[ BYTECODE: filename ]=== */
        <opcode listing>
        /* ===[ END BYTECODE: filename ]=== */
        /* ===[ DECOMPILED: filename ]=== */
        <best-effort PHP reconstruction>
        /* ===[ END DECOMPILED: filename ]=== */

eval() always outputs:
        /* ===[ EVAL SOURCE: filename(line) : eval()'d code ]=== */
        <the string passed to eval — the runtime-decrypted payload>
        /* ===[ END EVAL SOURCE: ... ]=== */
        + bytecode and decompiled as above
```

Each filename is output **at most once per process**, so cache hits,
repeated includes, and the dual-hook OPcache path produce no duplicate output.

## Download

Prebuilt binaries for Linux x86_64 and Windows x64 are attached to every
[release](https://github.com/GarethWright/php-src/releases).

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `inspector.output_dir` | _(unset)_ | Directory to write per-script `.inspector` files. When set, stderr is silent and PHP runs as a transparent drop-in. |

Set via `-d` flag or `php.ini`:

```ini
; php.ini
inspector.output_dir = /var/log/php-inspector
```

```bash
# per-invocation
./php -d inspector.output_dir=/tmp/out script.php
```

Each intercepted script produces one file named after the sanitised script
path, e.g. `/tmp/out/var_www_app_index.php.inspector`. The normal PHP stdout
stream is untouched.

## Usage

### Drop-in mode (output dir set — no stderr noise)

```bash
mkdir /tmp/inspector_out
./php -d inspector.output_dir=/tmp/inspector_out /path/to/app/entry.php
ls /tmp/inspector_out/   # one .inspector file per loaded script
```

### Inspect a file on disk (stderr mode)

```bash
# Source is printed, then the script runs normally
./php /path/to/script.php 2>source.txt
```

### Inspect a file-cache-only (no source) deployment

```bash
# Point OPcache at the .bin cache directory; source files need not exist
PHP_INI_SCAN_DIR= ./php \
  -d opcache.enable_cli=1 \
  -d opcache.file_cache=/path/to/bin-cache \
  -d opcache.file_cache_only=1 \
  -d inspector.output_dir=/tmp/decoded \
  /path/to/entry.php
```

The inspector will dump the decoded op_array for every cached script.

### Intercept an IonCube / Zend Guard / SourceGuardian protected app

```bash
# The loader extension decrypts before returning the op_array;
# our hook sees the plaintext opcodes.
./php \
  -d extension=/path/to/ioncube_loader.so \
  -d inspector.output_dir=/tmp/decoded \
  app.php
```

### Catch eval-based obfuscators

```bash
# Anything eval()'d — including multi-layer nested evals — is captured.
./php -d inspector.output_dir=/tmp/decoded obfuscated.php
grep -rl "EVAL SOURCE" /tmp/decoded/
```

### Separate inspector output from application output (stderr mode)

```bash
./php app.php 2>inspector.txt 1>app_output.txt
```

## Building from source

### Linux

```bash
sudo apt-get install -y build-essential autoconf bison re2c \
  libxml2-dev libsqlite3-dev

./buildconf --force
./configure --disable-all --enable-cli --enable-opcache --with-phar
make -j$(nproc)
# binary is at sapi/cli/php
```

### Windows

See [Build your own PHP on Windows](https://wiki.php.net/internals/windows/stepbystepbuild_sdk_2).
Use the same configure flags as above with `nmake` instead of `make`.

## Coverage and limitations

| Scenario | Covered |
|----------|---------|
| Normal `.php` files | Yes — source verbatim |
| OPcache shared-memory cache hits | Yes — via `zend_accel_load_script` patch |
| OPcache file cache (`file_cache_only=1`) | Yes — via `zend_accel_load_script` patch |
| Preloaded scripts (`opcache.preload`) | Yes — patch fires at preload time |
| Commercial loaders (IonCube, Zend Guard, etc.) | Yes — hook sees decrypted op_array |
| `eval()` payloads (all nesting levels) | Yes — `zend_compile_string` hook |
| Phar archives | Yes — source not on disk → bytecode dump |
| Native-code-only execution (no Zend VM) | No — no op_array exists |

---

# The PHP Interpreter

PHP is a popular general-purpose scripting language that is especially suited to
web development. Fast, flexible and pragmatic, PHP powers everything from your
blog to the most popular websites in the world.

PHP is distributed under the [Modified BSD License](LICENSE)
(SPDX-License-Identifier: `BSD-3-Clause`).

[![Test](https://github.com/php/php-src/actions/workflows/test.yml/badge.svg)](https://github.com/php/php-src/actions/workflows/test.yml)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/php.svg)](https://issues.oss-fuzz.com/issues?q=project:php)

## Documentation

The PHP manual is available at [php.net/docs](https://www.php.net/docs).

## Installation

### Prebuilt packages and binaries

Prebuilt packages and binaries can be used to get up and running fast with PHP.

For Windows, the PHP binaries can be obtained from
[windows.php.net](https://windows.php.net). After extracting the archive the
`*.exe` files are ready to use.

For other systems, see the [installation chapter](https://www.php.net/install).

### Building PHP source code

*For Windows, see [Build your own PHP on Windows](https://wiki.php.net/internals/windows/stepbystepbuild_sdk_2).*

For a minimal PHP build from Git, you will need autoconf, bison, and re2c. For
a default build, you will additionally need libxml2 and libsqlite3.

On Ubuntu, you can install these using:

```shell
sudo apt install -y pkg-config build-essential autoconf bison re2c libxml2-dev libsqlite3-dev
```

On Fedora, you can install these using:

```shell
sudo dnf install re2c bison autoconf make ccache libxml2-devel sqlite-devel
```

On MacOS, you can install these using `brew`:

```shell
brew install autoconf bison re2c libiconv libxml2 sqlite
```

or with `MacPorts`:

```shell
sudo port install autoconf bison re2c libiconv libxml2 sqlite3
```

Generate configure:

```shell
./buildconf
```

Configure your build. `--enable-debug` is recommended for development, see
`./configure --help` for a full list of options.

```shell
# For development
./configure --enable-debug
# For production
./configure
```

Build PHP. To speed up the build, specify the maximum number of jobs using the
`-j` argument:

```shell
make -j4
```

The number of jobs should usually match the number of available cores, which
can be determined using `nproc`.

## Testing PHP source code

PHP ships with an extensive test suite, the command `make test` is used after
successful compilation of the sources to run this test suite.

It is possible to run tests using multiple cores by setting `-jN` in
`TEST_PHP_ARGS` or `TESTS`:

```shell
make TEST_PHP_ARGS=-j4 test
```

Shall run `make test` with a maximum of 4 concurrent jobs: Generally the maximum
number of jobs should not exceed the number of cores available.

Use the `TEST_PHP_ARGS` or `TESTS` variable to test only specific directories:

```shell
make TESTS=tests/lang/ test
```

The [qa.php.net](https://qa.php.net) site provides more detailed info about
testing and quality assurance.

## Installing PHP built from source

After a successful build (and test), PHP may be installed with:

```shell
make install
```

Depending on your permissions and prefix, `make install` may need superuser
permissions.

## PHP extensions

Extensions provide additional functionality on top of PHP. PHP consists of many
essential bundled extensions. Additional extensions can be found in the PHP
Extension Community Library - [PECL](https://pecl.php.net).

## Contributing

The PHP source code is located in the Git repository at
[github.com/php/php-src](https://github.com/php/php-src). Contributions are most
welcome by forking the repository and sending a pull request.

Discussions are done on GitHub, but depending on the topic can also be relayed
to the official PHP developer mailing list internals@lists.php.net.

New features require an RFC and must be accepted by the developers. See
[Request for comments - RFC](https://wiki.php.net/rfc) and
[Voting on PHP features](https://wiki.php.net/rfc/voting) for more information
on the process.

Bug fixes don't require an RFC. If the bug has a GitHub issue, reference it in
the commit message using `GH-NNNNNN`. Use `#NNNNNN` for tickets in the old
[bugs.php.net](https://bugs.php.net) bug tracker.

    Fix GH-7815: php_uname doesn't recognise latest Windows versions
    Fix #55371: get_magic_quotes_gpc() throws deprecation warning

See [Git workflow](https://wiki.php.net/vcs/gitworkflow) for details on how pull
requests are merged.

### Guidelines for contributors

See further documents in the repository for more information on how to
contribute:

- [Contributing to PHP](/CONTRIBUTING.md)
- [PHP coding standards](/CODING_STANDARDS.md)
- [Internal documentation](https://php.github.io/php-src/)
- [Mailing list rules](/docs/mailinglist-rules.md)
- [PHP release process](/docs/release-process.md)

## Credits

For the list of people who've put work into PHP, please see the
[PHP credits page](https://www.php.net/credits.php).
