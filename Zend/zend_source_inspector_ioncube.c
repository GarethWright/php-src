/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source Inspector: IonCube 15.x bytecode decoder    |
   +----------------------------------------------------------------------+
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/
#ifdef _WIN32

#include "php.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "zend_compile.h"
#include "zend_source_inspector_memscan.h"
#include "zend_source_inspector_ioncube.h"

/* =========================================================================
 * IonCube DLL base detection
 * ========================================================================= */

static uint64_t ic_get_dll_base(void)
{
	HMODULE h = GetModuleHandle("ioncube_loader_win_8.4.dll");
	if (!h) h = GetModuleHandle("ioncube_loader_win_8.5.dll");
	return h ? (uint64_t)(uintptr_t)h : 0ULL;
}

/* =========================================================================
 * Known opcode handler table
 * (DLL offset → PHP-level operation name)
 *
 * Discovered by comparing method behaviour with decoded handler addresses.
 * All offsets are relative to the IonCube DLL base (typically 0x180000000).
 * ========================================================================= */

typedef struct {
	uint64_t dll_offset;  /* byte offset from DLL base */
	const char *name;     /* human-readable opcode name */
	const char *php_fmt;  /* printf format for PHP reconstruction (NULL=unknown) */
} ic_handler_entry;

static const ic_handler_entry IC_HANDLERS[] = {
	/* FETCH_PROPERTY: reads an object property by hash.
	 * Operands in block header: hash word[2], slot word[7].
	 * handler at DLL+0x7750 = string comparison/lookup loop */
	{0x007750, "FETCH_PROPERTY",    "$this->{prop}"},
	{0x00B6600, "FETCH_PROP_B",     "$this->{prop}"},
	{0x00B6650, "FETCH_PROP_C",     "$this->{prop}"},

	/* Dispatch trampoline at +0x1F41F0 (always appears in block[+0x40]) */
	{0x01F41F0, "DISPATCH_TRAMPOLINE", NULL},

	/* Terminate sentinel */
	{0, NULL, NULL}
};

static const ic_handler_entry *ic_lookup_handler(uint64_t dll_offset)
{
	for (int i = 0; IC_HANDLERS[i].name; i++) {
		if (IC_HANDLERS[i].dll_offset == dll_offset)
			return &IC_HANDLERS[i];
	}
	return NULL;
}

/* =========================================================================
 * CBC-XOR cipher
 * key = 0x23B1 initially; dec = enc XOR key; key_next = enc
 * IonCube's slot[1] always ends with 0x0000, resetting key per block.
 * ========================================================================= */

#define IC_INITIAL_KEY  0x23B1U

typedef struct {
	uint16_t key;
} ic_cipher;

static void ic_cipher_init(ic_cipher *c) { c->key = IC_INITIAL_KEY; }

static uint16_t ic_decrypt_word(ic_cipher *c, uint16_t enc)
{
	uint16_t dec = enc ^ c->key;
	c->key = enc;
	return dec;
}

/* Decrypt a sequence of 16-bit LE words from `data` (size bytes) */
static void ic_decrypt_buf(ic_cipher *c, const uint8_t *data, size_t size,
                            uint16_t *out, size_t max_out, size_t *n_out)
{
	*n_out = 0;
	for (size_t i = 0; i + 1 < size && *n_out < max_out; i += 2) {
		uint16_t enc = (uint16_t)data[i] | ((uint16_t)data[i+1] << 8);
		out[(*n_out)++] = ic_decrypt_word(c, enc);
	}
}

/* =========================================================================
 * Block instruction
 * ========================================================================= */

typedef struct {
	/* Decoded block header operand words (up to 16) */
	uint16_t hdr[16];
	size_t   hdr_count;

	/* First decoded opcode word from slot[1] */
	uint16_t opcode;
	bool     have_opcode;

	/* DLL handler from slot[1]'s embedded ptr */
	uint64_t handler_dll_off;
	const ic_handler_entry *handler;

	/* Is this the last block (no linked-list next)? */
	bool is_last;
} ic_instr;

/* Read one 96-byte block at `block_addr`, decode header and slot[1] opcode.
 * `cipher` is the running CBC state coming in; it is advanced by this call.
 * Returns true on success. */
static bool ic_read_block(
    const void *block_addr,
    ic_cipher  *cipher,
    uint64_t    ic_base,
    ic_instr   *out_instr,
    void      **out_next_block)
{
	if (!memscan_is_readable(block_addr, 0x60)) return false;

	uint8_t blk[0x60];
	SIZE_T nr = 0;
	if (!ReadProcessMemory(GetCurrentProcess(), block_addr, blk, sizeof(blk), &nr)
	    || nr < 0x60)
		return false;

	memset(out_instr, 0, sizeof(*out_instr));
	*out_next_block = NULL;

	/* --- Decrypt block header (first 32 bytes = encrypted operand stream) --- */
	ic_cipher hdr_cipher = *cipher; /* save cipher before header */
	ic_decrypt_buf(cipher, blk, 32,
	               out_instr->hdr, 16, &out_instr->hdr_count);

	/* Restore cipher: header decryption is a peek — the REAL cipher advance
	 * comes from processing slot[0] and slot[1] operand data.  Reset to the
	 * saved state so we process slots with the same key progression. */
	*cipher = hdr_cipher;

	/* --- Process slot[0] (type-A operand context) --- */
	void *slot0_ptr = NULL;
	memcpy(&slot0_ptr, blk + 0x20, 8);

	if (slot0_ptr && memscan_is_readable(slot0_ptr, 32)) {
		uint8_t s0[32]; SIZE_T s0r = 0;
		ReadProcessMemory(GetCurrentProcess(), slot0_ptr, s0, sizeof(s0), &s0r);
		/* Process 32 bytes through cipher (advances key for slot[1]) */
		uint16_t dummy[16]; size_t dn;
		ic_decrypt_buf(cipher, s0, s0r, dummy, 16, &dn);
	}

	/* --- Process slot[1] (main operand data) --- */
	void *slot1_ptr = NULL;
	memcpy(&slot1_ptr, blk + 0x28, 8);

	if (slot1_ptr && memscan_is_readable(slot1_ptr, 32)) {
		uint8_t s1[32]; SIZE_T s1r = 0;
		ReadProcessMemory(GetCurrentProcess(), slot1_ptr, s1, sizeof(s1), &s1r);

		/* The interpreter does: MOV RCX, [RDI+R15]; XOR AX, [RCX]
		 * RCX = slot1_ptr (the instruction array element value itself).
		 * The 2 bytes are read DIRECTLY from slot1_ptr — single indirection only.
		 * (The first 8 bytes of s1 embed another pointer for DLL patching, but
		 *  the opcode bytes come from the first 2 bytes of s1 itself.) */
		if (s1r >= 2) {
			uint16_t enc16 = (uint16_t)s1[0] | ((uint16_t)s1[1] << 8);
			out_instr->opcode = enc16 ^ cipher->key;
			out_instr->have_opcode = true;
			cipher->key = enc16;  /* CBC: ciphertext becomes next key */
		}

		/* Bytes 8-31 of slot[1]: DLL handler pointers (unencrypted).
		 * Pick the first DLL-range pointer as the primary handler. */
		for (size_t x = 8; x + 8 <= 32; x += 8) {
			uint64_t v = 0;
			memcpy(&v, s1 + x, 8);
			if (ic_base && v >= ic_base && v < ic_base + 0x400000ULL) {
				out_instr->handler_dll_off = v - ic_base;
				out_instr->handler = ic_lookup_handler(out_instr->handler_dll_off);
				break;
			}
		}

		/* Process remaining slot[1] bytes through cipher
		 * (slot[1] ends with 0x0000 → key resets to 0x0000) */
		uint16_t dummy[16]; size_t dn;
		ic_decrypt_buf(cipher, s1, s1r, dummy, 16, &dn);
	}

	/* --- Read slot[2] = next block (linked list) --- */
	void *slot2_ptr = NULL;
	memcpy(&slot2_ptr, blk + 0x30, 8);
	if (slot2_ptr && (uintptr_t)slot2_ptr > 0x10000)
		*out_next_block = slot2_ptr;
	else
		out_instr->is_last = true;

	/* --- slot[3] should be NULL --- */
	void *slot3_ptr = NULL;
	memcpy(&slot3_ptr, blk + 0x38, 8);
	if (!slot3_ptr && !*out_next_block)
		out_instr->is_last = true;

	return true;
}

/* =========================================================================
 * PHP code reconstruction helpers
 * ========================================================================= */

/* =========================================================================
 * Property hash table
 * IonCube stores a 16-bit hash of the property name in the block header.
 * Populated from observed method behaviour on WHMCS 9.0.4.
 * ========================================================================= */
typedef struct { uint16_t hash; const char *name; } ic_prop_entry;
static const ic_prop_entry IC_PROPS[] = {
	{0x8CC7, "licenseKey"},
	/* more to populate as additional methods are analysed */
	{0, NULL}
};
static const char *ic_prop_name(uint16_t hash)
{
	for (int i = 0; IC_PROPS[i].name; i++)
		if (IC_PROPS[i].hash == hash) return IC_PROPS[i].name;
	return NULL;
}

/*
 * The block header (first 32 bytes, CBC-XOR decrypted) encodes instruction
 * operands in a fixed layout.  Based on reverse engineering of WHMCS 9.0.4:
 *
 *   hdr[0..1] = instruction metadata (type/class, ~0x0005 for FETCH_PROPERTY)
 *   hdr[2]    = property hash (e.g. 0x8CC7 = hash of "licenseKey")
 *   hdr[3]    = related value
 *   hdr[4..5] = secondary values
 *   hdr[6]    = first variable slot (e.g. 0x0051)
 *   hdr[7]    = property slot / result variable (e.g. 0x0053 = slot 83)
 *
 * The slot index (hdr[7]) corresponds to one of the op_array->vars entries,
 * which holds the property name as a PHP string.
 */
static void ic_reconstruct_php(
    FILE              *out,
    const ic_instr    *instr,
    const zend_op_array *op_array,
    int                block_idx)
{
	if (!instr->have_opcode) {
		fprintf(out, "  /* instr[%d]: (opcode decode failed) */\n", block_idx);
		return;
	}

	/* Look up the handler name */
	const char *hname = instr->handler ? instr->handler->name : "UNKNOWN";

	/* Extract operand words from decoded header */
	uint16_t prop_hash = (instr->hdr_count > 2) ? instr->hdr[2] : 0;
	uint16_t prop_slot = (instr->hdr_count > 7) ? instr->hdr[7] : 0;

	/* Try to resolve property name from op_array->vars
	 * (op_array->vars[slot] holds the variable name PHP string) */
	const char *prop_name = NULL;
	if (prop_slot < op_array->last_var && op_array->vars) {
		zend_string *vn = op_array->vars[prop_slot];
		if (vn) prop_name = ZSTR_VAL(vn);
	}

	/* Also try the IC property hash table */
	const char *ic_prop = ic_prop_name(prop_hash);
	if (!prop_name && ic_prop) prop_name = ic_prop;

	if (instr->opcode == 0x0730 || instr->handler_dll_off == 0x007750
	    || instr->handler_dll_off == 0x00B6600
	    || instr->handler_dll_off == 0x00B6650) {
		/* FETCH_PROPERTY */
		if (prop_name) {
			fprintf(out, "  $this->%s", prop_name);
		} else if (prop_hash) {
			fprintf(out, "  $this->{prop_hash:0x%04x}", prop_hash);
		} else {
			fprintf(out, "  FETCH_PROPERTY");
		}
		fprintf(out, "  /* opcode=0x%04x slot=%u hash=0x%04x DLL+0x%05" PRIx64 "=%s */\n",
			instr->opcode, prop_slot, prop_hash,
			instr->handler_dll_off, hname);
	} else {
		/* Unknown opcode: emit raw info */
		fprintf(out, "  /* opcode=0x%04x DLL+0x%05" PRIx64 "=%s",
			instr->opcode, instr->handler_dll_off, hname);
		if (instr->hdr_count > 0) {
			fprintf(out, " hdr=[");
			for (size_t i = 0; i < instr->hdr_count && i < 8; i++)
				fprintf(out, "%s0x%04x", i ? "," : "", instr->hdr[i]);
			fprintf(out, "]");
		}
		fprintf(out, " */\n");
	}
}

/* =========================================================================
 * Dynamic execution tracer
 * =========================================================================
 *
 * Strategy:
 *   - For each IonCube-encoded class, we replace read_property / write_property
 *     in its object handler vtable with wrappers that record {prop, value, R/W}.
 *   - A global function pointer hooks zend_execute_internal so we catch built-in
 *     PHP function calls (strlen, php_sapi_name, etc.) made from IC code.
 *   - A small stack tracks which IC method is currently executing, so logged
 *     operations are attributed to the right method frame.
 *   - When a trace ends (ic_trace_end) we emit clean PHP from the log.
 * ========================================================================= */

/* Maximum nesting depth for concurrent IC method calls */
#define IC_TRACE_MAX_DEPTH   32
/* Maximum property/call operations to record per method call */
#define IC_TRACE_MAX_OPS     256
/* Maximum number of classes whose handlers we have patched */
#define IC_TRACE_MAX_CLASSES 128

typedef enum {
	IC_OP_READ_PROP,    /* $this->prop (read) */
	IC_OP_WRITE_PROP,   /* $this->prop = value (write) */
	IC_OP_INTERNAL_CALL /* builtin_func(args) -> retval */
} ic_op_kind;

/* One traced operation */
typedef struct {
	ic_op_kind kind;

	/* For IC_OP_READ_PROP / IC_OP_WRITE_PROP */
	char prop_name[128];
	char value_str[512];  /* zval formatted as PHP literal */

	/* For IC_OP_INTERNAL_CALL */
	char func_name[128];
	char args_str[512];
	char retval_str[256];
} ic_op;

/* Per-method trace frame */
typedef struct {
	const zend_op_array *op_array;
	ic_op                ops[IC_TRACE_MAX_OPS];
	int                  nops;
} ic_trace_frame;

/* Global trace stack */
static ic_trace_frame  ic_trace_stack[IC_TRACE_MAX_DEPTH];
static int             ic_trace_depth = 0;   /* 0 = idle */

/* ---- Saved object-handler entries ---- */
typedef struct {
	zend_class_entry              *ce;
	zend_object_handlers          *orig_handlers; /* the vtable in the CE */
	zend_object_handlers           saved;          /* copy of originals */
} ic_class_hook;

static ic_class_hook  ic_hooked_classes[IC_TRACE_MAX_CLASSES];
static int            ic_hooked_count = 0;

/* ---- Saved zend_execute_internal pointer ---- */
static void (*ic_orig_execute_internal)(
    zend_execute_data *execute_data, zval *return_value) = NULL;

/* =========================================================================
 * Helpers: format a zval as a short PHP literal string
 * ========================================================================= */

static void ic_fmt_zval(const zval *zv, char *buf, size_t bufsz)
{
	if (!zv) { snprintf(buf, bufsz, "null"); return; }
	switch (Z_TYPE_P(zv)) {
		case IS_NULL:   snprintf(buf, bufsz, "null");  return;
		case IS_FALSE:  snprintf(buf, bufsz, "false"); return;
		case IS_TRUE:   snprintf(buf, bufsz, "true");  return;
		case IS_LONG:
			snprintf(buf, bufsz, ZEND_LONG_FMT, Z_LVAL_P(zv));
			return;
		case IS_DOUBLE:
			snprintf(buf, bufsz, "%G", Z_DVAL_P(zv));
			return;
		case IS_STRING: {
			size_t slen = Z_STRLEN_P(zv);
			const char *sv = Z_STRVAL_P(zv);
			size_t out_i = 0;
			if (out_i < bufsz - 1) buf[out_i++] = '"';
			for (size_t i = 0; i < slen && out_i < bufsz - 5; i++) {
				unsigned char c = (unsigned char)sv[i];
				if (c == '"')       { buf[out_i++] = '\\'; buf[out_i++] = '"'; }
				else if (c == '\\') { buf[out_i++] = '\\'; buf[out_i++] = '\\'; }
				else if (c == '\n') { buf[out_i++] = '\\'; buf[out_i++] = 'n'; }
				else if (c == '\r') { buf[out_i++] = '\\'; buf[out_i++] = 'r'; }
				else if (c == '\t') { buf[out_i++] = '\\'; buf[out_i++] = 't'; }
				else if (c < 0x20)  { out_i += (size_t)snprintf(buf+out_i, bufsz-out_i, "\\x%02x", c); }
				else                { buf[out_i++] = (char)c; }
			}
			if (slen > 64 && out_i < bufsz - 4) {
				buf[out_i++] = '.'; buf[out_i++] = '.'; buf[out_i++] = '.';
			}
			if (out_i < bufsz - 1) buf[out_i++] = '"';
			buf[out_i] = '\0';
			return;
		}
		case IS_ARRAY:
			snprintf(buf, bufsz, "[/*array(%d)*/]", (int)zend_array_count(Z_ARRVAL_P(zv)));
			return;
		case IS_OBJECT: {
			zend_class_entry *ce = Z_OBJCE_P(zv);
			snprintf(buf, bufsz, "/*object(%s)*/",
				(ce && ce->name) ? ZSTR_VAL(ce->name) : "?");
			return;
		}
		default:
			snprintf(buf, bufsz, "/*type=%d*/", Z_TYPE_P(zv));
			return;
	}
}

/* Push a new operation onto the innermost active trace frame.
 * Returns NULL if no trace is active or buffer is full. */
static ic_op *ic_trace_push(void)
{
	if (ic_trace_depth <= 0) return NULL;
	ic_trace_frame *frame = &ic_trace_stack[ic_trace_depth - 1];
	if (frame->nops >= IC_TRACE_MAX_OPS) return NULL;
	ic_op *op = &frame->ops[frame->nops++];
	memset(op, 0, sizeof(*op));
	return op;
}

/* =========================================================================
 * Property handler hooks
 * ========================================================================= */

static zval *ic_trace_read_property(
    zend_object *object, zend_string *member, int type,
    void **cache_slot, zval *rv)
{
	/* Find the original handler for this class */
	zend_class_entry *ce = object->ce;
	zend_object_read_property_t orig_read = NULL;

	for (int i = 0; i < ic_hooked_count; i++) {
		if (ic_hooked_classes[i].ce == ce) {
			orig_read = ic_hooked_classes[i].saved.read_property;
			break;
		}
	}

	/* Call original handler to get the real value */
	zval *result = NULL;
	if (orig_read) {
		result = orig_read(object, member, type, cache_slot, rv);
	}

	/* Record the operation if a trace is active */
	if (ic_trace_depth > 0 && member) {
		ic_op *op = ic_trace_push();
		if (op) {
			op->kind = IC_OP_READ_PROP;
			snprintf(op->prop_name, sizeof(op->prop_name), "%s", ZSTR_VAL(member));
			if (result) {
				ic_fmt_zval(result, op->value_str, sizeof(op->value_str));
			} else {
				snprintf(op->value_str, sizeof(op->value_str), "null");
			}
		}
	}

	return result;
}

static zval *ic_trace_write_property(
    zend_object *object, zend_string *member, zval *value,
    void **cache_slot)
{
	/* Find the original handler */
	zend_class_entry *ce = object->ce;
	zend_object_write_property_t orig_write = NULL;

	for (int i = 0; i < ic_hooked_count; i++) {
		if (ic_hooked_classes[i].ce == ce) {
			orig_write = ic_hooked_classes[i].saved.write_property;
			break;
		}
	}

	/* Record the operation before the write */
	if (ic_trace_depth > 0 && member) {
		ic_op *op = ic_trace_push();
		if (op) {
			op->kind = IC_OP_WRITE_PROP;
			snprintf(op->prop_name, sizeof(op->prop_name), "%s", ZSTR_VAL(member));
			if (value) {
				ic_fmt_zval(value, op->value_str, sizeof(op->value_str));
			} else {
				snprintf(op->value_str, sizeof(op->value_str), "null");
			}
		}
	}

	/* Call original handler */
	zval *result = NULL;
	if (orig_write) {
		result = orig_write(object, member, value, cache_slot);
	}
	return result;
}

/* =========================================================================
 * zend_execute_internal hook
 * ========================================================================= */

static void ic_trace_execute_internal(
    zend_execute_data *execute_data, zval *return_value)
{
	/* Call through first */
	if (ic_orig_execute_internal) {
		ic_orig_execute_internal(execute_data, return_value);
	} else {
		execute_internal(execute_data, return_value);
	}

	/* Record if a trace is active and this is a real internal-function frame */
	if (ic_trace_depth > 0
	    && execute_data
	    && execute_data->func
	    && execute_data->func->type == ZEND_INTERNAL_FUNCTION) {

		ic_op *op = ic_trace_push();
		if (op) {
			op->kind = IC_OP_INTERNAL_CALL;

			/* Function name */
			const zend_function *fn = execute_data->func;
			const char *fname = NULL;
			if (fn->common.function_name) {
				fname = ZSTR_VAL(fn->common.function_name);
			}
			snprintf(op->func_name, sizeof(op->func_name), "%s",
				fname ? fname : "?");

			/* Build args string safely (cap at 8 to avoid out-of-frame reads) */
			uint32_t nargs = ZEND_CALL_NUM_ARGS(execute_data);
			if (nargs > 8) nargs = 8;
			char *ap = op->args_str;
			size_t aremain = sizeof(op->args_str);
			for (uint32_t i = 0; i < nargs && i < 4 && aremain > 4; i++) {
				zval *arg = ZEND_CALL_ARG(execute_data, i + 1);
				char abuf[128];
				ic_fmt_zval(arg, abuf, sizeof(abuf));
				size_t written = (size_t)snprintf(ap, aremain,
					"%s%s", (i > 0 ? ", " : ""), abuf);
				if (written >= aremain) break;
				ap += written;
				aremain -= written;
			}
			if (ZEND_CALL_NUM_ARGS(execute_data) > 4 && aremain > 8) {
				snprintf(ap, aremain, ", /*+%u*/",
					ZEND_CALL_NUM_ARGS(execute_data) - 4);
			}

			/* Return value */
			if (return_value && Z_TYPE_P(return_value) != IS_UNDEF) {
				ic_fmt_zval(return_value, op->retval_str, sizeof(op->retval_str));
			} else {
				snprintf(op->retval_str, sizeof(op->retval_str), "void");
			}
		}
	}
}

/* =========================================================================
 * Public tracer API
 * ========================================================================= */

void ic_tracer_global_init(void)
{
	ic_trace_depth  = 0;
	ic_hooked_count = 0;

	/* Hook zend_execute_internal (if not already hooked) */
	if (zend_execute_internal != ic_trace_execute_internal) {
		ic_orig_execute_internal = zend_execute_internal;
		zend_execute_internal    = ic_trace_execute_internal;
	}
}

void ic_tracer_global_shutdown(void)
{
	/* Restore zend_execute_internal */
	if (zend_execute_internal == ic_trace_execute_internal) {
		zend_execute_internal = ic_orig_execute_internal;
		ic_orig_execute_internal = NULL;
	}

	/* Note: we do NOT dereference CEs here because the class_table may already
	 * have been torn down by the time shutdown is called.  The patched vtable
	 * slots are on our stack (ic_patched_handlers[]) so they will be gone when
	 * the next request starts anyway.  Just reset counters. */
	ic_hooked_count = 0;
	ic_trace_depth  = 0;
}

/* Per-class patched handlers: we allocate a COPY of the vtable per class
 * so we never write into the shared std_object_handlers or read-only pages. */
static zend_object_handlers ic_patched_handlers[IC_TRACE_MAX_CLASSES];

void ic_install_class_trace(zend_class_entry *ce)
{
	if (!ce) return;

	/* Check if already hooked */
	for (int i = 0; i < ic_hooked_count; i++) {
		if (ic_hooked_classes[i].ce == ce) return;
	}
	if (ic_hooked_count >= IC_TRACE_MAX_CLASSES) return;

	const zend_object_handlers *h = ce->default_object_handlers;
	if (!h) return;

	/* Skip if both slots already point to our hooks */
	if (h->read_property  == ic_trace_read_property &&
	    h->write_property == ic_trace_write_property) return;

	int idx = ic_hooked_count++;
	ic_class_hook *slot = &ic_hooked_classes[idx];
	slot->ce            = ce;
	slot->orig_handlers = (zend_object_handlers *)h;  /* keep for restore */
	slot->saved         = *h;  /* full copy of original handlers */

	/* Make a private copy of the vtable and patch the two slots we care about.
	 * Then point the CE at our copy so we never write to shared pages. */
	ic_patched_handlers[idx] = *h;  /* copy all handlers */
	ic_patched_handlers[idx].read_property  = ic_trace_read_property;
	ic_patched_handlers[idx].write_property = ic_trace_write_property;
	ce->default_object_handlers = &ic_patched_handlers[idx];
}

void ic_trace_begin(const zend_op_array *op_array)
{
	if (ic_trace_depth >= IC_TRACE_MAX_DEPTH) return;

	ic_trace_frame *frame = &ic_trace_stack[ic_trace_depth++];
	frame->op_array = op_array;
	frame->nops     = 0;
}

void ic_trace_end(FILE *out)
{
	if (ic_trace_depth <= 0 || !out) return;

	ic_trace_depth--;
	ic_trace_frame *frame = &ic_trace_stack[ic_trace_depth];
	const zend_op_array *oa = frame->op_array;

	if (!oa || frame->nops == 0) return;

	const char *fname = oa->function_name
		? ZSTR_VAL(oa->function_name) : "(anon)";
	const char *cname = (oa->scope && oa->scope->name)
		? ZSTR_VAL(oa->scope->name) : NULL;

	fprintf(out, "\n/* ===[ DYNAMIC TRACE: %s%s%s  (%d ops) ]=== */\n",
		cname ? cname : "", cname ? "::" : "", fname, frame->nops);
	fprintf(out, "<?php\n");
	if (cname) {
		fprintf(out, "/* Traced: %s::%s() */\n", cname, fname);
	} else {
		fprintf(out, "/* Traced: %s() */\n", fname);
	}

	/* Walk the operations and emit PHP-ish reconstructions */
	for (int i = 0; i < frame->nops; i++) {
		const ic_op *op = &frame->ops[i];
		switch (op->kind) {

		case IC_OP_READ_PROP:
			fprintf(out, "$v%d = $this->%s;  /* = %s */\n",
				i, op->prop_name, op->value_str);
			break;

		case IC_OP_WRITE_PROP:
			fprintf(out, "$this->%s = %s;\n",
				op->prop_name, op->value_str);
			break;

		case IC_OP_INTERNAL_CALL:
			if (op->retval_str[0] && strcmp(op->retval_str, "void") != 0
			    && strcmp(op->retval_str, "null") != 0) {
				fprintf(out, "$v%d = %s(%s);  /* = %s */\n",
					i, op->func_name, op->args_str, op->retval_str);
			} else {
				fprintf(out, "%s(%s);\n",
					op->func_name, op->args_str);
			}
			break;
		}
	}

	fprintf(out, "/* ===[ END DYNAMIC TRACE: %s%s%s ]=== */\n\n",
		cname ? cname : "", cname ? "::" : "", fname);
	fflush(out);
}

void ic_trace_internal_call(
    zend_execute_data *execute_data, zval *return_value)
{
	/* Thin wrapper: the hook is already installed globally.
	 * This function exists for external callers that want to report
	 * an internal call outside the automatic hook (e.g. zend_call_function). */
	(void)execute_data; (void)return_value;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

void zend_source_inspector_decode_ioncube(
    FILE *out,
    const zend_op_array *op_array)
{
	if (!out || !op_array) return;

	uint64_t ic_base = ic_get_dll_base();

	/* --- Locate bc_ptr via reserved[3] → slot+0x88 → descriptor+0x08 --- */
	void *slot = op_array->reserved[3];
	if (!slot) return;

	void *method_ptr = NULL;
	{
		SIZE_T nr = 0;
		if (!memscan_is_readable((char*)slot + 0x88, 8)) return;
		ReadProcessMemory(GetCurrentProcess(), (char*)slot + 0x88,
		                  &method_ptr, 8, &nr);
		if (nr != 8 || !method_ptr) return;
	}

	void *bc_ptr   = NULL;
	uint32_t bc_sz = 0;
	{
		uint8_t desc[0x20]; SIZE_T nr = 0;
		if (!memscan_is_readable(method_ptr, 0x20)) return;
		ReadProcessMemory(GetCurrentProcess(), method_ptr, desc, sizeof(desc), &nr);
		if (nr < 0x20) return;
		memcpy(&bc_ptr, desc + 0x08, 8);
		memcpy(&bc_sz,  desc + 0x10, 4);
	}

	if (!bc_ptr || !bc_sz) return;

	const char *fname = op_array->function_name
		? ZSTR_VAL(op_array->function_name) : "(anon)";
	const char *cname = (op_array->scope && op_array->scope->name)
		? ZSTR_VAL(op_array->scope->name) : NULL;

	fprintf(out, "\n/* ===[ IONCUBE VM: %s%s%s  "
		"(bc_ptr=%p  blocks=~%u  key=0x%04x) ]=== */\n",
		cname ? cname : "", cname ? "::" : "", fname,
		bc_ptr, bc_sz / 96, IC_INITIAL_KEY);

	/* --- Walk the linked list of 96-byte instruction blocks --- */
	ic_cipher cipher;
	ic_cipher_init(&cipher);

	void *block       = bc_ptr;
	int   block_idx   = 0;
	void *seen[64];   /* dedup: avoid infinite loops */
	int   seen_count  = 0;
	bool  have_output = false;

	/* Track unique (opcode, hash, slot) tuples to collapse type variants */
	struct { uint16_t opcode; uint16_t hash; uint16_t slot; } uniq[64];
	int uniq_count = 0;

	while (block && block_idx < 64) {
		/* Dedup check — avoid infinite loops */
		bool already_seen = false;
		for (int s = 0; s < seen_count; s++) {
			if (seen[s] == block) { already_seen = true; break; }
		}
		if (already_seen) break;
		if (seen_count < 64) seen[seen_count++] = block;

		/* Bounds check */
		ptrdiff_t off = (char*)block - (char*)bc_ptr;
		if (off < 0 || (uint32_t)off >= bc_sz + 0x200) break;

		ic_instr instr;
		void *next_block = NULL;

		if (!ic_read_block(block, &cipher, ic_base, &instr, &next_block))
			break;

		/* Collapse duplicate (opcode, hash, slot) tuples from type-variant blocks */
		if (instr.have_opcode) {
			uint16_t h = (instr.hdr_count > 2) ? instr.hdr[2] : 0;
			uint16_t s = (instr.hdr_count > 7) ? instr.hdr[7] : 0;
			bool dup = false;
			for (int u = 0; u < uniq_count; u++) {
				if (uniq[u].opcode == instr.opcode &&
				    uniq[u].hash   == h &&
				    uniq[u].slot   == s) {
					dup = true; break;
				}
			}
			if (!dup) {
				if (uniq_count < 64) {
					uniq[uniq_count].opcode = instr.opcode;
					uniq[uniq_count].hash   = h;
					uniq[uniq_count].slot   = s;
					uniq_count++;
				}
				ic_reconstruct_php(out, &instr, op_array, uniq_count - 1);
				have_output = true;
			}
		} else {
			ic_reconstruct_php(out, &instr, op_array, block_idx);
			have_output = true;
		}

		if (instr.is_last || !next_block) break;
		block = next_block;
		block_idx++;
	}

	if (!have_output) {
		fprintf(out, "  /* (no decodeable instructions found) */\n");
	}

	fprintf(out, "/* ===[ END IONCUBE VM: %s%s%s ]=== */\n\n",
		cname ? cname : "", cname ? "::" : "", fname);
	fflush(out);
}

#endif /* _WIN32 */
