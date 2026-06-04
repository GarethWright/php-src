/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source Inspector: IonCube memory scanner           |
   +----------------------------------------------------------------------+
   | Scans op_array->reserved[] slots and nearby heap memory to find      |
   | IonCube's internal bytecode structures.  Windows-only.               |
   |                                                                       |
   | IonCube 15.x returns stub op_arrays (last==0) and runs decoded code  |
   | through its own interpreter.  The pointer to IonCube's internal      |
   | data is stored in one of the reserved[] slots.  We dump those        |
   | regions so their format can be analyzed.                             |
   +----------------------------------------------------------------------+
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/

#ifdef _WIN32

/* Include PHP headers first — they pull in windows.h through
 * zend_portability.h on Windows, which avoids redefinition conflicts. */
#include "php.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "zend.h"
#include "zend_compile.h"

#include "zend_source_inspector.h"
#include "zend_source_inspector_memscan.h"

/* =========================================================================
 * Hex dump helpers
 * ========================================================================= */

#define DUMP_WIDTH 16   /* bytes per line */
#define DUMP_MAX   4096 /* max bytes per region dump */

static void memscan_hexdump(FILE *out, const void *ptr, size_t len,
                            uintptr_t base_addr)
{
	const unsigned char *p = (const unsigned char *)ptr;
	size_t i, j;
	for (i = 0; i < len; i += DUMP_WIDTH) {
		fprintf(out, "  %016" PRIxPTR "  ", base_addr + i);
		for (j = 0; j < DUMP_WIDTH; j++) {
			if (i + j < len)
				fprintf(out, "%02x ", p[i + j]);
			else
				fprintf(out, "   ");
			if (j == 7) fprintf(out, " ");
		}
		fprintf(out, " |");
		for (j = 0; j < DUMP_WIDTH && i + j < len; j++) {
			unsigned char c = p[i + j];
			fprintf(out, "%c", (c >= 0x20 && c < 0x7f) ? c : '.');
		}
		fprintf(out, "|\n");
	}
}

/* =========================================================================
 * Extract printable strings ≥ min_len from a buffer
 * ========================================================================= */
#define STR_MIN 4

static void memscan_strings(FILE *out, const void *ptr, size_t len)
{
	const unsigned char *p = (const unsigned char *)ptr;
	size_t i, start = 0;
	bool in_str = false;

	for (i = 0; i <= len; i++) {
		unsigned char c = (i < len) ? p[i] : 0;
		bool printable = (c >= 0x20 && c < 0x7f);
		if (printable) {
			if (!in_str) { start = i; in_str = true; }
		} else {
			if (in_str && (i - start) >= STR_MIN) {
				fprintf(out, "  str@+%04zx: \"", start);
				for (size_t k = start; k < i; k++) fprintf(out, "%c", p[k]);
				fprintf(out, "\"\n");
			}
			in_str = false;
		}
	}
}

/* =========================================================================
 * Probe one pointer: verify readable, dump region
 * ========================================================================= */

static bool memscan_is_readable(const void *ptr, size_t len)
{
	if (!ptr) return false;
	uintptr_t addr = (uintptr_t)ptr;
	/* Filter obvious non-pointers: below 64 KiB or above user-space */
	if (addr < 0x10000 || addr > (uintptr_t)0x00007FFFFFFFFFFF) return false;

	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
	if (mbi.State != MEM_COMMIT) return false;
	DWORD prot = mbi.Protect & ~PAGE_GUARD & ~PAGE_NOCACHE & ~PAGE_WRITECOMBINE;
	return (prot == PAGE_READONLY || prot == PAGE_READWRITE ||
	        prot == PAGE_EXECUTE_READ || prot == PAGE_EXECUTE_READWRITE ||
	        prot == PAGE_EXECUTE_WRITECOPY || prot == PAGE_WRITECOPY);
}

static void memscan_dump_region(FILE *out, const void *ptr,
                                 const char *label, int slot_idx)
{
	if (!memscan_is_readable(ptr, 1)) return;

	MEMORY_BASIC_INFORMATION mbi;
	VirtualQuery(ptr, &mbi, sizeof(mbi));

	/* Calculate how many bytes to dump: from ptr to end of region, capped */
	uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
	uintptr_t from = (uintptr_t)ptr;
	size_t avail = (region_end > from) ? (size_t)(region_end - from) : 0;
	size_t dump_len = avail < DUMP_MAX ? avail : DUMP_MAX;
	if (dump_len == 0) return;

	const char *prot_name = "?";
	switch (mbi.Protect & 0xFF) {
		case PAGE_READONLY:          prot_name = "RO";  break;
		case PAGE_READWRITE:         prot_name = "RW";  break;
		case PAGE_EXECUTE_READ:      prot_name = "RE";  break;
		case PAGE_EXECUTE_READWRITE: prot_name = "RWE"; break;
		default: break;
	}

	fprintf(out,
		"\n/* --- reserved[%d] = 0x%016" PRIxPTR "  [%s, %zu-byte region] --- */\n",
		slot_idx, (uintptr_t)ptr, prot_name, (size_t)mbi.RegionSize);

	/* Allocate a local copy to avoid TOCTOU races */
	unsigned char *buf = (unsigned char *)malloc(dump_len);
	if (!buf) return;
	SIZE_T read_bytes = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), ptr, buf, dump_len, &read_bytes)) {
		free(buf);
		fprintf(out, "  (ReadProcessMemory failed: %lu)\n", GetLastError());
		return;
	}

	fprintf(out, "/* Hex dump (%zu bytes from 0x%016" PRIxPTR "): */\n",
		read_bytes, from);
	memscan_hexdump(out, buf, read_bytes, from);

	fprintf(out, "/* Extracted strings: */\n");
	memscan_strings(out, buf, read_bytes);

	free(buf);
	fflush(out);
}

/* =========================================================================
 * Public API: scan reserved[] slots for one op_array
 * ========================================================================= */

void zend_source_inspector_memscan_op_array(
	const zend_op_array *op_array, FILE *out)
{
	if (!op_array || !out) return;

	bool found_any = false;
	for (int i = 0; i < ZEND_MAX_RESERVED_RESOURCES; i++) {
		void *v = op_array->reserved[i];
		if (!v) continue;
		uintptr_t addr = (uintptr_t)v;
		/* Skip small integers (e.g. slot indices stored as (void*)N) */
		if (addr < 0x10000) {
			fprintf(out, "/* reserved[%d] = 0x%" PRIxPTR " (small int, not a ptr) */\n",
				i, addr);
			continue;
		}
		found_any = true;
		memscan_dump_region(out, v, "reserved", i);
	}
	if (!found_any) {
		fprintf(out, "/* All reserved[] slots are NULL or small ints — "
			"IonCube may use a different association mechanism */\n");
	}

	/*
	 * Follow the pointer at slot offset +0x80 — in IonCube 15.x this is
	 * the per-method internal data pointer (distinct from the class dispatch
	 * table that reserved[3] itself lives in).  Dumping it reveals the
	 * method-specific bytecode without the shared class-level preamble.
	 */
	if (found_any) {
		/* reserved[3] is the slot pointer; read 8 bytes at slot+0x80 */
		void *slot = op_array->reserved[3];
		/* The method-specific data pointer is at slot+0x88 (8 padding bytes
		 * at +0x80 precede it in IonCube 15.x's dispatch slot layout). */
		if (slot && memscan_is_readable((char*)slot + 0x88, 8)) {
			void *method_ptr = NULL;
			SIZE_T nr = 0;
			ReadProcessMemory(GetCurrentProcess(),
				(char*)slot + 0x88, &method_ptr, sizeof(method_ptr), &nr);
			if (nr == sizeof(method_ptr) && method_ptr &&
			    (uintptr_t)method_ptr > 0x10000) {
				fprintf(out,
					"\n/* --- method_ptr (slot+0x88) = 0x%016" PRIxPTR " --- */\n",
					(uintptr_t)method_ptr);
				memscan_dump_region(out, method_ptr, "method_ptr", -1);

				/*
				 * Parse the 128-byte descriptor at the start of method_ptr:
				 *   +0x00 [8B]: class vtable ptr (same for all methods)
				 *   +0x08 [8B]: bytecode ptr (per-method encrypted blob)
				 *   +0x10 [4B]: bytecode size (LE uint32)
				 *   +0x14 [8B]: per-method encryption key
				 */
				uint8_t desc[0x20];
				SIZE_T desc_read = 0;
				if (ReadProcessMemory(GetCurrentProcess(),
				                      method_ptr, desc, sizeof(desc),
				                      &desc_read) && desc_read == sizeof(desc)) {
					void *bc_ptr = NULL;
					memcpy(&bc_ptr, desc + 0x08, sizeof(bc_ptr));
					uint32_t bc_size = 0;
					memcpy(&bc_size, desc + 0x10, sizeof(bc_size));
					uint8_t enc_key[8];
					memcpy(enc_key, desc + 0x14, 8);

					fprintf(out,
						"\n/* DESCRIPTOR: bc_ptr=0x%016" PRIxPTR
						"  size=%u  key=%02x%02x%02x%02x%02x%02x%02x%02x */\n",
						(uintptr_t)bc_ptr, bc_size,
						enc_key[0],enc_key[1],enc_key[2],enc_key[3],
						enc_key[4],enc_key[5],enc_key[6],enc_key[7]);

					if (bc_ptr && bc_size > 0 && bc_size < 0x40000 &&
					    memscan_is_readable(bc_ptr, 1)) {
						size_t dump_bc = bc_size < DUMP_MAX ? bc_size : DUMP_MAX;
						unsigned char *bc_buf = (unsigned char *)malloc(dump_bc);
						if (bc_buf) {
							SIZE_T bc_read = 0;
							ReadProcessMemory(GetCurrentProcess(),
								bc_ptr, bc_buf, dump_bc, &bc_read);
							if (bc_read > 0) {
								fprintf(out,
									"/* ENCRYPTED BYTECODE (%zu bytes): */\n",
									bc_read);
								memscan_hexdump(out, bc_buf, bc_read,
									(uintptr_t)bc_ptr);

								/* Attempt XOR with 8-byte key */
								fprintf(out,
									"\n/* XOR-DECRYPTED attempt"
									" (key=%02x%02x%02x%02x%02x%02x%02x%02x): */\n",
									enc_key[0],enc_key[1],enc_key[2],enc_key[3],
									enc_key[4],enc_key[5],enc_key[6],enc_key[7]);
								for (size_t x = 0; x < bc_read; x++)
									bc_buf[x] ^= enc_key[x % 8];
								memscan_hexdump(out, bc_buf, bc_read,
									(uintptr_t)bc_ptr);
								memscan_strings(out, bc_buf, bc_read);
							}
							free(bc_buf);
						}
					}
				}
			}
		}
	}
}

/* =========================================================================
 * Heap / address-space scan: look for IonCube's private allocations
 * =========================================================================
 * Strategy: walk all committed non-image private pages.  Scan each for
 * embedded ASCII strings ≥ 6 chars that look like PHP identifiers
 * (contain '\\', ':', letters, digits).  Also look for pointer-density
 * (many consecutive 8-byte values that are valid heap addresses) which
 * would indicate IonCube's internal dispatch/vtable structures.
 * ========================================================================= */

#define HEAP_SCAN_CHUNK    (64 * 1024)  /* read 64 KiB at a time */
#define HEAP_SCAN_MAX_MB   256          /* don't scan more than 256 MB total */
#define ID_STR_MIN         6
#define PTR_DENSITY_MIN    8            /* ≥8 consecutive valid ptrs → interesting */

/* Returns true if s looks like a PHP qualified name: has letter/digit + possibly :: or \ */
static bool looks_like_php_name(const char *s, size_t len)
{
	if (len < ID_STR_MIN) return false;
	bool has_alpha = false, has_sep = false;
	for (size_t i = 0; i < len; i++) {
		char c = s[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_')
			has_alpha = true;
		if (c == '\\' || (i > 0 && c == ':' && s[i-1] == ':'))
			has_sep = true;
	}
	return has_alpha; /* sep is bonus but not required */
}

/* Estimate pointer density in a 64-byte window */
static int pointer_density(const unsigned char *p, size_t avail)
{
	int count = 0;
	size_t slots = (avail >= 64) ? 8 : (avail / 8);
	for (size_t i = 0; i < slots; i++) {
		uintptr_t v;
		memcpy(&v, p + i * 8, sizeof(v));
		if (v >= 0x10000 && v <= (uintptr_t)0x00007FFFFFFFFFFF)
			count++;
	}
	return count;
}

/* Write a region summary without a full hex dump */
static void memscan_region_summary(FILE *out, uintptr_t addr,
                                    size_t region_size, size_t dump_bytes,
                                    int interesting_strings,
                                    int pointer_windows)
{
	fprintf(out, "\n/* HEAP REGION 0x%016" PRIxPTR
		" size=0x%zx  interesting_strings=%d  ptr_windows=%d */\n",
		addr, region_size, interesting_strings, pointer_windows);
}

void zend_source_inspector_memscan_heap(FILE *out)
{
	if (!out) return;

	fprintf(out, "\n/* ===[ HEAP SCAN: searching for IonCube private allocations ]=== */\n");
	fflush(out);

	SYSTEM_INFO si;
	GetSystemInfo(&si);

	unsigned char *addr = (unsigned char *)si.lpMinimumApplicationAddress;
	unsigned char *limit = (unsigned char *)si.lpMaximumApplicationAddress;

	size_t total_scanned = 0;
	size_t max_scan = (size_t)HEAP_SCAN_MAX_MB * 1024 * 1024;
	int regions_dumped = 0;

	unsigned char *buf = (unsigned char *)malloc(HEAP_SCAN_CHUNK);
	if (!buf) { fprintf(out, "/* malloc failed */\n"); return; }

	while (addr < limit && total_scanned < max_scan) {
		MEMORY_BASIC_INFORMATION mbi;
		if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) {
			addr += 4096;
			continue;
		}

		size_t region_size = mbi.RegionSize;
		unsigned char *region_base = (unsigned char *)mbi.BaseAddress;

		/* Only scan committed private (non-image) RW pages.
		 * Skip image pages (PHP/IonCube DLL code sections). */
		bool interesting =
			(mbi.State == MEM_COMMIT) &&
			(mbi.Type == MEM_PRIVATE) &&
			((mbi.Protect & PAGE_READWRITE) ||
			 (mbi.Protect & PAGE_EXECUTE_READWRITE));

		if (!interesting || region_size < 256) {
			addr = region_base + region_size;
			continue;
		}

		/* Scan up to HEAP_SCAN_CHUNK bytes of this region */
		size_t scan_here = region_size < HEAP_SCAN_CHUNK ? region_size : HEAP_SCAN_CHUNK;
		SIZE_T nread = 0;
		if (!ReadProcessMemory(GetCurrentProcess(), region_base,
		                       buf, scan_here, &nread) || nread == 0) {
			addr = region_base + region_size;
			continue;
		}

		total_scanned += nread;

		/* Count PHP-looking strings and pointer-dense windows */
		int interesting_strings = 0;
		int ptr_windows = 0;

		/* String search */
		size_t i = 0;
		while (i < nread) {
			unsigned char c = buf[i];
			if (c >= 0x20 && c < 0x7f) {
				size_t start = i;
				while (i < nread && buf[i] >= 0x20 && buf[i] < 0x7f) i++;
				size_t slen = i - start;
				if (slen >= ID_STR_MIN &&
				    looks_like_php_name((const char *)(buf + start), slen))
					interesting_strings++;
			} else {
				i++;
			}
		}

		/* Pointer density windows (every 64 bytes) */
		for (size_t w = 0; w + 64 <= nread; w += 64) {
			if (pointer_density(buf + w, 64) >= PTR_DENSITY_MIN)
				ptr_windows++;
		}

		/* Only report and dump regions with ≥2 interesting signals */
		if (interesting_strings >= 2 || ptr_windows >= 3) {
			memscan_region_summary(out, (uintptr_t)region_base,
				region_size, nread, interesting_strings, ptr_windows);

			/* Extract and show PHP-looking strings */
			i = 0;
			int str_count = 0;
			while (i < nread && str_count < 40) {
				unsigned char c = buf[i];
				if (c >= 0x20 && c < 0x7f) {
					size_t start = i;
					while (i < nread && buf[i] >= 0x20 && buf[i] < 0x7f) i++;
					size_t slen = i - start;
					if (slen >= ID_STR_MIN &&
					    looks_like_php_name((const char *)(buf + start), slen)) {
						fprintf(out, "  str@+%04zx: \"", start);
						for (size_t k = start; k < start + slen; k++)
							fprintf(out, "%c", buf[k]);
						fprintf(out, "\"\n");
						str_count++;
					}
				} else {
					i++;
				}
			}

			/* Also show first 128 bytes as hex to hint at structure */
			size_t preview = nread < 128 ? nread : 128;
			fprintf(out, "/* First %zu bytes: */\n", preview);
			memscan_hexdump(out, buf, preview, (uintptr_t)region_base);
			fflush(out);
			regions_dumped++;

			if (regions_dumped >= 50) {
				fprintf(out, "/* (scan limit reached: 50 interesting regions) */\n");
				break;
			}
		}

		addr = region_base + region_size;
	}

	free(buf);
	fprintf(out, "\n/* ===[ END HEAP SCAN: scanned %.1f MB, %d interesting regions ]=== */\n",
		(double)total_scanned / (1024.0 * 1024.0), regions_dumped);
	fflush(out);
}

#endif /* _WIN32 */
