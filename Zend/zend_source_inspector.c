/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source/Bytecode Inspector                          |
   +----------------------------------------------------------------------+
   | Hooks zend_compile_file so that for every PHP file interpreted:      |
   |   - If the source is readable, outputs it verbatim to stderr.        |
   |   - If only bytecode is available (e.g. opaque Phar / stream),       |
   |     outputs the opcode listing and a best-effort PHP reconstruction. |
   |                                                                      |
   | The hook is installed *after* all Zend extensions start, so it sits  |
   | on top of OPcache's persistent_compile_file when that is present.    |
   | OPcache-cached op_arrays still flow through our wrapper, allowing    |
   | source look-up by filename even for cache-hit paths.                 |
   +----------------------------------------------------------------------+
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifndef _WIN32
# include <unistd.h>   /* dup, dup2, STDERR_FILENO */
#endif

#include "php.h"
#include "zend.h"
#include "zend_compile.h"
#include "zend_stream.h"
#include "zend_vm_opcodes.h"
#include "Optimizer/zend_dump.h"
#include "zend_source_inspector.h"

/* =========================================================================
 * Hook management
 * ========================================================================= */

ZEND_API zend_op_array *(*zend_source_inspector_orig_compile)(
	zend_file_handle *file_handle, int type) = NULL;

ZEND_API zend_op_array *(*zend_source_inspector_orig_compile_string)(
	zend_string *source_string, const char *filename,
	zend_compile_position position) = NULL;

/* =========================================================================
 * php.ini: inspector.output_dir
 * =========================================================================
 * When set to a directory path, inspector output is written to per-script
 * files in that directory instead of stderr.  PHP then runs as a fully
 * transparent drop-in replacement — no extra output on stdout or stderr.
 *
 * File naming: the PHP filename is sanitized (path separators and special
 * chars replaced with underscores) and suffixed with .inspector.
 * Example: /var/www/app/index.php → {dir}/var_www_app_index.php.inspector
 * ========================================================================= */

#define INSPECTOR_MODULE_NUMBER  (-42)   /* unique negative — never clashes */

static char *inspector_output_dir_cfg = NULL;

static ZEND_INI_MH(inspector_on_output_dir_update)
{
	free(inspector_output_dir_cfg);
	inspector_output_dir_cfg =
		(new_value && ZSTR_LEN(new_value) > 0)
			? strdup(ZSTR_VAL(new_value)) : NULL;
	return SUCCESS;
}

/* ZEND_INI_BEGIN/END create: static const zend_ini_entry_def ini_entries[] */
ZEND_INI_BEGIN()
	ZEND_INI_ENTRY("inspector.output_dir", "", ZEND_INI_ALL,
		inspector_on_output_dir_update)
ZEND_INI_END()

/*
 * Open the output FILE* for one PHP script.  The caller must pass the result
 * to inspector_close_output() when done.  Returns stderr if no dir is set.
 */
static FILE *inspector_open_output(const char *php_filename)
{
	const char *dir = inspector_output_dir_cfg;
	if (!dir || !*dir) return stderr;

	/* Sanitize: keep alnum / dot / hyphen, collapse everything else to '_' */
	char safe[512];
	size_t si = 0;
	const char *p = php_filename;
	while (*p == '/') p++;          /* skip leading slashes */
	for (; *p && si < sizeof(safe) - 1; p++) {
		char c = *p;
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		    (c >= '0' && c <= '9') || c == '.' || c == '-') {
			safe[si++] = c;
		} else {
			if (si == 0 || safe[si - 1] != '_') safe[si++] = '_';
		}
	}
	while (si > 0 && safe[si - 1] == '_') si--;  /* trim trailing '_' */
	safe[si] = '\0';

	char path[1536];
	snprintf(path, sizeof(path), "%s/%s.inspector", dir, safe[0] ? safe : "unknown");

	FILE *fp = fopen(path, "w");
	return fp ? fp : stderr;
}

static void inspector_close_output(FILE *fp)
{
	if (fp && fp != stderr) fclose(fp);
}


/*
 * Deduplication table — tracks filenames already output this process.
 * Allocated persistently (malloc) so it survives across requests.
 * Uses Zend's HashTable with persistent=1 for bucket storage.
 */
static HashTable  inspector_seen_ht;
static bool       inspector_seen_initialized = false;

/*
 * Returns true and marks the filename as seen if this is the first time.
 * Returns false if we have already output this filename.
 */
static bool inspector_mark_seen(const char *filename)
{
	if (!inspector_seen_initialized) {
		zend_hash_init(&inspector_seen_ht, 64, NULL, NULL, /* persistent */ 1);
		inspector_seen_initialized = true;
	}
	size_t len = strlen(filename);
	if (zend_hash_str_exists(&inspector_seen_ht, filename, len)) {
		return false;
	}
	zend_hash_str_add_empty_element(&inspector_seen_ht, filename, len);
	return true;
}

/* =========================================================================
 * Source output
 * ========================================================================= */

static void inspector_output_source(
	FILE *out, const char *filename, const char *src, size_t len)
{
	fprintf(out, "\n/* ===[ PHP SOURCE: %s ]=== */\n", filename);
	fwrite(src, 1, len, out);
	if (len == 0 || src[len - 1] != '\n') fputc('\n', out);
	fprintf(out, "/* ===[ END SOURCE: %s ]=== */\n\n", filename);
	fflush(out);
}

/* =========================================================================
 * Bytecode output  (delegates to the existing zend_dump infrastructure)
 * ========================================================================= */

static void inspector_output_bytecode(FILE *out, const zend_op_array *op_array)
{
	const char *filename =
		op_array->filename ? ZSTR_VAL(op_array->filename) : "(unknown)";

	fprintf(out, "\n/* ===[ BYTECODE: %s ]=== */\n", filename);
	fflush(out);

	/*
	 * zend_dump_op_array always writes to stderr.  When our output target
	 * is a file we temporarily point file-descriptor 2 at that file so the
	 * dump lands there, then restore stderr afterwards.
	 */
	if (out == stderr) {
		zend_dump_op_array(op_array, ZEND_DUMP_LINE_NUMBERS, NULL, NULL);
	} else {
#ifdef _WIN32
		int saved_fd = _dup(_fileno(stderr));
		fflush(stderr); fflush(out);
		_dup2(_fileno(out), _fileno(stderr));
		zend_dump_op_array(op_array, ZEND_DUMP_LINE_NUMBERS, NULL, NULL);
		fflush(stderr);
		_dup2(saved_fd, _fileno(stderr)); _close(saved_fd);
#else
		int saved_fd = dup(STDERR_FILENO);
		if (saved_fd >= 0) {
			fflush(stderr); fflush(out);
			dup2(fileno(out), STDERR_FILENO);
			zend_dump_op_array(op_array, ZEND_DUMP_LINE_NUMBERS, NULL, NULL);
			fflush(stderr);
			dup2(saved_fd, STDERR_FILENO);
			close(saved_fd);
		} else {
			zend_dump_op_array(op_array, ZEND_DUMP_LINE_NUMBERS, NULL, NULL);
		}
#endif
	}

	fprintf(out, "/* ===[ END BYTECODE: %s ]=== */\n", filename);
	fflush(out);
}

/* =========================================================================
 * Decompiler  – best-effort reconstruction of PHP source from opcodes
 * =========================================================================
 *
 * Strategy
 * --------
 * We maintain an "expression table" (temps[]) keyed by the Zend temp/var
 * slot number.  As we walk opcodes linearly:
 *   - Computation opcodes store their result expression string into temps[].
 *   - Statement opcodes (ASSIGN, ECHO, RETURN, DO_FCALL, …) emit a PHP
 *     statement and clear the temp.
 *   - Jump opcodes are emitted as goto + label (no full CFG recovery).
 *   - Function calls are assembled via a call-stack: INIT_FCALL pushes a
 *     frame, SEND_* accumulates arguments, DO_FCALL pops and builds the
 *     call expression.
 *
 * This produces valid, readable PHP for straight-line code and simple
 * loops/conditionals.  Complex control flow is represented with goto labels
 * which a human reader can trivially convert back.
 * ========================================================================= */

#define DC_MAX_VARS       4096
#define DC_MAX_ARGS         64
#define DC_MAX_CALL_DEPTH   64

typedef struct {
	char *str;   /* heap-allocated expression string; NULL if slot is empty */
} dc_expr;

typedef struct {
	char *name;                  /* function / method name */
	char *object;                /* object / class for method/static calls */
	bool  is_static;
	bool  is_new;                /* new ClassName() */
	char *args[DC_MAX_ARGS];
	int   num_args;
} dc_call;

typedef struct {
	dc_expr     temps[DC_MAX_VARS];
	dc_call     call_stack[DC_MAX_CALL_DEPTH];
	int         call_depth;
	FILE       *out;
	int         indent;
	const zend_op_array *op_array;
	uint8_t    *is_jump_target; /* is_jump_target[i] != 0 → emit L%04u: label */
} dc_state;

/* ----- tiny helpers ---------------------------------------------------- */

static void dc_expr_set(dc_state *dc, uint32_t slot, const char *s)
{
	if (slot >= DC_MAX_VARS) return;
	free(dc->temps[slot].str);
	dc->temps[slot].str = s ? strdup(s) : NULL;
}

static char *dc_expr_get(dc_state *dc, uint32_t slot)
{
	if (slot < DC_MAX_VARS && dc->temps[slot].str) {
		return dc->temps[slot].str;
	}
	return NULL;
}

static char *dc_xasprintf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char buf[4096];
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	return strdup(buf);
}

static void dc_indent_print(dc_state *dc, const char *fmt, ...)
{
	for (int i = 0; i < dc->indent; i++) {
		fputs("    ", dc->out);
	}
	va_list ap;
	va_start(ap, fmt);
	vfprintf(dc->out, fmt, ap);
	va_end(ap);
	fputc('\n', dc->out);
}

/* ----- zval → quoted PHP literal --------------------------------------- */

static char *dc_fmt_zval(const zval *zv)
{
	char buf[512];
	switch (Z_TYPE_P(zv)) {
		case IS_NULL:   return strdup("null");
		case IS_FALSE:  return strdup("false");
		case IS_TRUE:   return strdup("true");
		case IS_LONG:
			snprintf(buf, sizeof(buf), ZEND_LONG_FMT, Z_LVAL_P(zv));
			return strdup(buf);
		case IS_DOUBLE:
			snprintf(buf, sizeof(buf), "%G", Z_DVAL_P(zv));
			/* Ensure it looks like a float, not an integer */
			if (!strchr(buf, '.') && !strchr(buf, 'e') &&
			    !strchr(buf, 'E') && !strchr(buf, 'n') &&
			    !strchr(buf, 'N')) {
				strncat(buf, ".0", sizeof(buf) - strlen(buf) - 1);
			}
			return strdup(buf);
		case IS_STRING: {
			size_t len = Z_STRLEN_P(zv);
			/* Worst case: every byte is escaped → 4 bytes; + 2 quotes + NUL */
			char *out = (char *)malloc(len * 4 + 3);
			if (!out) return strdup("\"?\"");
			char *p = out;
			*p++ = '"';
			for (size_t i = 0; i < len; i++) {
				unsigned char c = (unsigned char)Z_STRVAL_P(zv)[i];
				if      (c == '"')  { *p++ = '\\'; *p++ = '"'; }
				else if (c == '\\') { *p++ = '\\'; *p++ = '\\'; }
				else if (c == '\n') { *p++ = '\\'; *p++ = 'n'; }
				else if (c == '\r') { *p++ = '\\'; *p++ = 'r'; }
				else if (c == '\t') { *p++ = '\\'; *p++ = 't'; }
				else if (c < 0x20) { p += sprintf(p, "\\x%02x", c); }
				else                { *p++ = (char)c; }
			}
			*p++ = '"';
			*p = '\0';
			char *result = strdup(out);
			free(out);
			return result;
		}
		default:
			snprintf(buf, sizeof(buf), "/* zval_type=%d */", Z_TYPE_P(zv));
			return strdup(buf);
	}
}

/* ----- Operand → expression string ------------------------------------- */

/*
 * Returns a heap-allocated string.  Caller must free() it.
 * For temp/var slots we return a copy of whatever is cached in temps[],
 * or a placeholder like ~t5 if nothing is cached.
 */
static char *dc_operand(dc_state *dc, uint8_t type, znode_op op,
                        const zend_op *opline)
{
	if (type == IS_CONST) {
		const zval *zv = RT_CONSTANT(opline, op);
		return dc_fmt_zval(zv);
	}
	if (type == IS_CV) {
		uint32_t idx = EX_VAR_TO_NUM(op.var);
		if (idx < (uint32_t)dc->op_array->last_var) {
			return dc_xasprintf("$%s", ZSTR_VAL(dc->op_array->vars[idx]));
		}
		return dc_xasprintf("$v%u", idx);
	}
	if (type == IS_TMP_VAR || type == IS_VAR) {
		uint32_t idx = EX_VAR_TO_NUM(op.var);
		char *cached = dc_expr_get(dc, idx);
		if (cached) return strdup(cached);
		return dc_xasprintf("~t%u", idx);
	}
	return strdup("/*unused*/");
}

/* Shorthand: write expression into result slot */
static void dc_result(dc_state *dc, const zend_op *opline, const char *expr)
{
	/* Mask off IS_SMART_BRANCH_* flags that may be ORed into result_type
	 * for comparison opcodes immediately followed by a JMPZ/JMPNZ. */
	uint8_t core_type = opline->result_type &
	    ~(uint8_t)(IS_SMART_BRANCH_JMPZ | IS_SMART_BRANCH_JMPNZ);
	if (core_type == IS_TMP_VAR ||
	    core_type == IS_VAR     ||
	    core_type == IS_CV) {
		uint32_t idx = EX_VAR_TO_NUM(opline->result.var);
		dc_expr_set(dc, idx, expr);
	}
}

/* ----- binary-op table ------------------------------------------------- */

static const char *dc_binop_str(uint8_t opcode)
{
	switch (opcode) {
		case ZEND_ADD:                 return "+";
		case ZEND_SUB:                 return "-";
		case ZEND_MUL:                 return "*";
		case ZEND_DIV:                 return "/";
		case ZEND_MOD:                 return "%";
		case ZEND_POW:                 return "**";
		case ZEND_SL:                  return "<<";
		case ZEND_SR:                  return ">>";
		case ZEND_CONCAT:              return ".";
		case ZEND_FAST_CONCAT:         return ".";
		case ZEND_BW_OR:               return "|";
		case ZEND_BW_AND:              return "&";
		case ZEND_BW_XOR:              return "^";
		case ZEND_IS_IDENTICAL:        return "===";
		case ZEND_IS_NOT_IDENTICAL:    return "!==";
		case ZEND_IS_EQUAL:            return "==";
		case ZEND_IS_NOT_EQUAL:        return "!=";
		case ZEND_IS_SMALLER:          return "<";
		case ZEND_IS_SMALLER_OR_EQUAL: return "<=";
		case ZEND_SPACESHIP:           return "<=>";
		case ZEND_BOOL_XOR:            return "xor";
		case ZEND_CASE:                return "==";
		case ZEND_CASE_STRICT:         return "===";
		default:                       return NULL;
	}
}

/* ----- assign-op table ------------------------------------------------- */

static const char *dc_assignop_str(uint32_t ev)
{
	switch (ev) {
		case ZEND_ADD:    return "+=";
		case ZEND_SUB:    return "-=";
		case ZEND_MUL:    return "*=";
		case ZEND_DIV:    return "/=";
		case ZEND_MOD:    return "%=";
		case ZEND_POW:    return "**=";
		case ZEND_SL:     return "<<=";
		case ZEND_SR:     return ">>=";
		case ZEND_CONCAT: return ".=";
		case ZEND_BW_OR:  return "|=";
		case ZEND_BW_AND: return "&=";
		case ZEND_BW_XOR: return "^=";
		default:          return "OP=";
	}
}

/* ----- jump-target map ------------------------------------------------- */

static void dc_build_jump_map(dc_state *dc)
{
	const zend_op_array *op_array = dc->op_array;
	uint32_t n = op_array->last;
	const zend_op *ops = op_array->opcodes;

	dc->is_jump_target = (uint8_t *)calloc(n, 1);
	if (!dc->is_jump_target) return;

	for (uint32_t i = 0; i < n; i++) {
		const zend_op *op = &ops[i];
		uint32_t t;
		switch (op->opcode) {
			case ZEND_JMP:
				t = (uint32_t)(OP_JMP_ADDR(op, op->op1) - ops);
				if (t < n) dc->is_jump_target[t] = 1;
				break;
			case ZEND_JMPZ:
			case ZEND_JMPNZ:
			case ZEND_JMPZ_EX:
			case ZEND_JMPNZ_EX:
			case ZEND_JMP_SET:
			case ZEND_COALESCE:
				t = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
				if (t < n) dc->is_jump_target[t] = 1;
				break;
			case ZEND_CATCH:
				/* op2 is a jump target when IS_UNUSED */
				if (op->op2_type == IS_UNUSED) {
					t = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
					if (t < n) dc->is_jump_target[t] = 1;
				}
				break;
			case ZEND_FE_RESET_R:
			case ZEND_FE_RESET_RW:
				t = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
				if (t < n) dc->is_jump_target[t] = 1;
				break;
			case ZEND_FE_FETCH_R:
			case ZEND_FE_FETCH_RW:
				/* extended_value is a relative jump offset */
				t = i + 1 + (op->extended_value / sizeof(zend_op));
				if (t < n) dc->is_jump_target[t] = 1;
				break;
			default:
				break;
		}
	}
}

/* ----- main decompiler pass ------------------------------------------- */

static void dc_run(dc_state *dc)
{
	const zend_op_array *oa = dc->op_array;
	uint32_t num_ops = oa->last;
	const zend_op *ops = oa->opcodes;
	char buf[4096];

	/* Emit a function header comment if this is a named function */
	if (oa->function_name) {
		if (oa->scope) {
			dc_indent_print(dc, "/* %s::%s() */",
				ZSTR_VAL(oa->scope->name),
				ZSTR_VAL(oa->function_name));
		} else {
			dc_indent_print(dc, "/* function %s() */",
				ZSTR_VAL(oa->function_name));
		}
	}

	for (uint32_t i = 0; i < num_ops; i++) {
		const zend_op *op = &ops[i];
		char *e1 = NULL, *e2 = NULL, *ev = NULL;

		/* Jump-target label */
		if (dc->is_jump_target && dc->is_jump_target[i]) {
			fprintf(dc->out, "L%04u:\n", i);
		}

		/* ----  binary ops (handled before the switch) ---- */
		{
			const char *bop = dc_binop_str(op->opcode);
			if (bop) {
				e1  = dc_operand(dc, op->op1_type, op->op1, op);
				e2  = dc_operand(dc, op->op2_type, op->op2, op);
				snprintf(buf, sizeof(buf), "(%s %s %s)", e1, bop, e2);
				dc_result(dc, op, buf);
				goto next;
			}
		}

		switch (op->opcode) {

		/* ---- NOP / cleanup ---- */
		case ZEND_NOP:
		case ZEND_FREE:
		case ZEND_FE_FREE:
		case ZEND_EXT_STMT:
		case ZEND_EXT_NOP:
		case ZEND_EXT_FCALL_BEGIN:
		case ZEND_EXT_FCALL_END:
		case ZEND_TICKS:
		case ZEND_OP_DATA:  /* consumed by preceding compound opcode */
			break;

		/* ---- Variable / value movement ---- */
		case ZEND_QM_ASSIGN:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_result(dc, op, e1);
			break;

		case ZEND_MAKE_REF:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "&%s", e1);
			dc_result(dc, op, buf);
			break;

		/* ---- Assignment ---- */
		case ZEND_ASSIGN:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "%s = %s;", e1, e2);
			if (op->result_type != IS_UNUSED) {
				dc_result(dc, op, e1);
			}
			break;

		case ZEND_ASSIGN_REF:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "%s = &%s;", e1, e2);
			break;

		case ZEND_ASSIGN_OP:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "%s %s %s;",
				e1, dc_assignop_str(op->extended_value), e2);
			break;

		case ZEND_ASSIGN_DIM: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = (op->op2_type != IS_UNUSED)
				 ? dc_operand(dc, op->op2_type, op->op2, op) : NULL;
			/* value is in the next OP_DATA */
			if (i + 1 < num_ops && ops[i + 1].opcode == ZEND_OP_DATA) {
				const zend_op *data = &ops[i + 1];
				ev = dc_operand(dc, data->op1_type, data->op1, data);
				if (e2) {
					dc_indent_print(dc, "%s[%s] = %s;", e1, e2, ev);
				} else {
					dc_indent_print(dc, "%s[] = %s;", e1, ev);
				}
				i++;
			}
			break;
		}

		case ZEND_ASSIGN_OBJ: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			if (i + 1 < num_ops && ops[i + 1].opcode == ZEND_OP_DATA) {
				const zend_op *data = &ops[i + 1];
				ev = dc_operand(dc, data->op1_type, data->op1, data);
				dc_indent_print(dc, "%s->%s = %s;", e1, e2, ev);
				i++;
			}
			break;
		}

		case ZEND_ASSIGN_STATIC_PROP: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			if (i + 1 < num_ops && ops[i + 1].opcode == ZEND_OP_DATA) {
				const zend_op *data = &ops[i + 1];
				ev = dc_operand(dc, data->op1_type, data->op1, data);
				dc_indent_print(dc, "%s::%s = %s;", e2, e1, ev);
				i++;
			}
			break;
		}

		/* ---- Inc/dec ---- */
		case ZEND_PRE_INC:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "++%s;", e1);
			} else {
				snprintf(buf, sizeof(buf), "++%s", e1);
				dc_result(dc, op, buf);
			}
			break;

		case ZEND_PRE_DEC:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "--%s;", e1);
			} else {
				snprintf(buf, sizeof(buf), "--%s", e1);
				dc_result(dc, op, buf);
			}
			break;

		case ZEND_POST_INC:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "%s++;", e1);
			} else {
				snprintf(buf, sizeof(buf), "%s++", e1);
				dc_result(dc, op, buf);
			}
			break;

		case ZEND_POST_DEC:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "%s--;", e1);
			} else {
				snprintf(buf, sizeof(buf), "%s--", e1);
				dc_result(dc, op, buf);
			}
			break;

		/* ---- Unary operators ---- */
		case ZEND_BW_NOT:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "~%s", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_BOOL_NOT:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "!%s", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_BOOL:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "(bool)%s", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_CAST: {
			const char *cast_str;
			switch (op->extended_value) {
				case IS_NULL:   cast_str = "(null)";   break;
				case IS_LONG:   cast_str = "(int)";    break;
				case IS_DOUBLE: cast_str = "(float)";  break;
				case IS_STRING: cast_str = "(string)"; break;
				case IS_ARRAY:  cast_str = "(array)";  break;
				case IS_OBJECT: cast_str = "(object)"; break;
				default:        cast_str = "(bool)";   break;
			}
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "%s%s", cast_str, e1);
			dc_result(dc, op, buf);
			break;
		}

		/* ---- Output ---- */
		case ZEND_ECHO:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_indent_print(dc, "echo %s;", e1);
			break;

		/* ---- Return ---- */
		case ZEND_RETURN:
		case ZEND_RETURN_BY_REF:
		case ZEND_GENERATOR_RETURN:
			if (op->op1_type == IS_UNUSED) {
				dc_indent_print(dc, "return;");
			} else {
				e1 = dc_operand(dc, op->op1_type, op->op1, op);
				dc_indent_print(dc, "return %s;", e1);
			}
			break;

		case ZEND_THROW:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_indent_print(dc, "throw %s;", e1);
			break;

		/* ---- Function / method calls ---- */
		case ZEND_INIT_FCALL:
		case ZEND_INIT_FCALL_BY_NAME:
		case ZEND_INIT_NS_FCALL_BY_NAME:
		case ZEND_INIT_USER_CALL: {
			if (dc->call_depth < DC_MAX_CALL_DEPTH) {
				dc_call *call = &dc->call_stack[dc->call_depth++];
				memset(call, 0, sizeof(*call));
				if (op->op2_type == IS_CONST) {
					const zval *zv = RT_CONSTANT(op, op->op2);
					if (Z_TYPE_P(zv) == IS_STRING) {
						call->name = strdup(Z_STRVAL_P(zv));
					}
				}
				if (!call->name) {
					e2 = dc_operand(dc, op->op2_type, op->op2, op);
					call->name = e2; e2 = NULL;
				}
			}
			break;
		}

		case ZEND_INIT_DYNAMIC_CALL: {
			if (dc->call_depth < DC_MAX_CALL_DEPTH) {
				dc_call *call = &dc->call_stack[dc->call_depth++];
				memset(call, 0, sizeof(*call));
				call->name = dc_operand(dc, op->op2_type, op->op2, op);
			}
			break;
		}

		case ZEND_INIT_METHOD_CALL: {
			if (dc->call_depth < DC_MAX_CALL_DEPTH) {
				dc_call *call = &dc->call_stack[dc->call_depth++];
				memset(call, 0, sizeof(*call));
				call->object = dc_operand(dc, op->op1_type, op->op1, op);
				if (op->op2_type == IS_CONST) {
					const zval *zv = RT_CONSTANT(op, op->op2);
					if (Z_TYPE_P(zv) == IS_STRING)
						call->name = strdup(Z_STRVAL_P(zv));
				}
				if (!call->name)
					call->name = dc_operand(dc, op->op2_type, op->op2, op);
			}
			break;
		}

		case ZEND_INIT_STATIC_METHOD_CALL: {
			if (dc->call_depth < DC_MAX_CALL_DEPTH) {
				dc_call *call = &dc->call_stack[dc->call_depth++];
				memset(call, 0, sizeof(*call));
				call->is_static = true;
				if (op->op1_type == IS_CONST) {
					const zval *zv = RT_CONSTANT(op, op->op1);
					if (Z_TYPE_P(zv) == IS_STRING)
						call->object = strdup(Z_STRVAL_P(zv));
				} else if (op->op1_type != IS_UNUSED) {
					call->object = dc_operand(dc, op->op1_type, op->op1, op);
				}
				if (op->op2_type == IS_CONST) {
					const zval *zv = RT_CONSTANT(op, op->op2);
					if (Z_TYPE_P(zv) == IS_STRING)
						call->name = strdup(Z_STRVAL_P(zv));
				} else if (op->op2_type != IS_UNUSED) {
					call->name = dc_operand(dc, op->op2_type, op->op2, op);
				}
				if (!call->name) call->name = strdup("__callStatic");
			}
			break;
		}

		case ZEND_NEW: {
			if (dc->call_depth < DC_MAX_CALL_DEPTH) {
				dc_call *call = &dc->call_stack[dc->call_depth++];
				memset(call, 0, sizeof(*call));
				call->is_new = true;
				if (op->op1_type == IS_CONST) {
					const zval *zv = RT_CONSTANT(op, op->op1);
					if (Z_TYPE_P(zv) == IS_STRING)
						call->name = strdup(Z_STRVAL_P(zv));
				}
				if (!call->name)
					call->name = dc_operand(dc, op->op1_type, op->op1, op);
			}
			break;
		}

		case ZEND_SEND_VAL:
		case ZEND_SEND_VAL_EX:
		case ZEND_SEND_VAR:
		case ZEND_SEND_VAR_EX:
		case ZEND_SEND_REF:
		case ZEND_SEND_FUNC_ARG:
		case ZEND_SEND_VAR_NO_REF:
		case ZEND_SEND_VAR_NO_REF_EX:
		case ZEND_SEND_ARRAY:
		case ZEND_SEND_USER: {
			if (dc->call_depth > 0) {
				dc_call *call = &dc->call_stack[dc->call_depth - 1];
				if (call->num_args < DC_MAX_ARGS) {
					e1 = dc_operand(dc, op->op1_type, op->op1, op);
					if (op->opcode == ZEND_SEND_REF) {
						char rbuf[512];
						snprintf(rbuf, sizeof(rbuf), "&%s", e1);
						free(e1);
						e1 = strdup(rbuf);
					}
					call->args[call->num_args++] = e1;
					e1 = NULL; /* ownership transferred */
				}
			}
			break;
		}

		case ZEND_SEND_UNPACK: {
			if (dc->call_depth > 0) {
				dc_call *call = &dc->call_stack[dc->call_depth - 1];
				if (call->num_args < DC_MAX_ARGS) {
					e1 = dc_operand(dc, op->op1_type, op->op1, op);
					char rbuf[512];
					snprintf(rbuf, sizeof(rbuf), "...%s", e1);
					free(e1); e1 = NULL;
					call->args[call->num_args++] = strdup(rbuf);
				}
			}
			break;
		}

		case ZEND_DO_FCALL:
		case ZEND_DO_ICALL:
		case ZEND_DO_UCALL:
		case ZEND_DO_FCALL_BY_NAME: {
			if (dc->call_depth > 0) {
				dc->call_depth--;
				dc_call *call = &dc->call_stack[dc->call_depth];

				/* Build argument list */
				char args_buf[2048] = {0};
				for (int a = 0; a < call->num_args; a++) {
					if (a > 0) strncat(args_buf, ", ",
						sizeof(args_buf) - strlen(args_buf) - 1);
					strncat(args_buf, call->args[a],
						sizeof(args_buf) - strlen(args_buf) - 1);
					free(call->args[a]);
				}

				if (call->is_new) {
					snprintf(buf, sizeof(buf), "new %s(%s)",
						call->name ? call->name : "?", args_buf);
				} else if (call->object) {
					snprintf(buf, sizeof(buf), "%s%s%s(%s)",
						call->object,
						call->is_static ? "::" : "->",
						call->name ? call->name : "?",
						args_buf);
				} else {
					snprintf(buf, sizeof(buf), "%s(%s)",
						call->name ? call->name : "?", args_buf);
				}

				free(call->name);
				free(call->object);

				if (op->result_type == IS_UNUSED) {
					dc_indent_print(dc, "%s;", buf);
				} else {
					dc_result(dc, op, buf);
				}
			}
			break;
		}

		/* ---- Fetch (variable / dim / property / constant) ---- */
		case ZEND_FETCH_R:
		case ZEND_FETCH_W:
		case ZEND_FETCH_RW:
		case ZEND_FETCH_IS:
		case ZEND_FETCH_FUNC_ARG:
		case ZEND_FETCH_UNSET: {
			/* op1 is the variable *name* (a string const or CV holding name) */
			if (op->op1_type == IS_CONST) {
				const zval *zv = RT_CONSTANT(op, op->op1);
				if (Z_TYPE_P(zv) == IS_STRING) {
					snprintf(buf, sizeof(buf), "$%s", Z_STRVAL_P(zv));
					dc_result(dc, op, buf);
					break;
				}
			}
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "${%s}", e1);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_FETCH_DIM_R:
		case ZEND_FETCH_DIM_W:
		case ZEND_FETCH_DIM_RW:
		case ZEND_FETCH_DIM_IS:
		case ZEND_FETCH_DIM_FUNC_ARG:
		case ZEND_FETCH_DIM_UNSET:
		case ZEND_FETCH_LIST_R: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->op2_type == IS_UNUSED) {
				snprintf(buf, sizeof(buf), "%s[]", e1);
			} else {
				e2 = dc_operand(dc, op->op2_type, op->op2, op);
				snprintf(buf, sizeof(buf), "%s[%s]", e1, e2);
			}
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_FETCH_OBJ_R:
		case ZEND_FETCH_OBJ_W:
		case ZEND_FETCH_OBJ_RW:
		case ZEND_FETCH_OBJ_IS:
		case ZEND_FETCH_OBJ_FUNC_ARG:
		case ZEND_FETCH_OBJ_UNSET: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			snprintf(buf, sizeof(buf), "%s->%s", e1, e2);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_FETCH_STATIC_PROP_R:
		case ZEND_FETCH_STATIC_PROP_W:
		case ZEND_FETCH_STATIC_PROP_RW:
		case ZEND_FETCH_STATIC_PROP_IS:
		case ZEND_FETCH_STATIC_PROP_FUNC_ARG:
		case ZEND_FETCH_STATIC_PROP_UNSET: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = (op->op2_type != IS_UNUSED)
				 ? dc_operand(dc, op->op2_type, op->op2, op)
				 : strdup("static");
			snprintf(buf, sizeof(buf), "%s::%s", e2, e1);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_FETCH_THIS:
			dc_result(dc, op, "$this");
			break;

		case ZEND_FETCH_CONSTANT:
		case ZEND_FETCH_CLASS_CONSTANT: {
			if (op->op2_type == IS_CONST) {
				const zval *zv = RT_CONSTANT(op, op->op2);
				if (Z_TYPE_P(zv) == IS_STRING) {
					if (op->op1_type != IS_UNUSED) {
						e1 = dc_operand(dc, op->op1_type, op->op1, op);
						snprintf(buf, sizeof(buf), "%s::%s", e1, Z_STRVAL_P(zv));
					} else {
						snprintf(buf, sizeof(buf), "%s", Z_STRVAL_P(zv));
					}
					dc_result(dc, op, buf);
				}
			}
			break;
		}

		case ZEND_FETCH_CLASS_NAME:
			if (op->extended_value == ZEND_FETCH_CLASS_SELF) {
				dc_result(dc, op, "self");
			} else if (op->extended_value == ZEND_FETCH_CLASS_PARENT) {
				dc_result(dc, op, "parent");
			} else if (op->extended_value == ZEND_FETCH_CLASS_STATIC) {
				dc_result(dc, op, "static");
			} else {
				dc_result(dc, op, "/*class*/");
			}
			break;

		case ZEND_FETCH_CLASS: {
			if (op->op2_type == IS_CONST) {
				const zval *zv = RT_CONSTANT(op, op->op2);
				if (Z_TYPE_P(zv) == IS_STRING) {
					dc_result(dc, op, Z_STRVAL_P(zv));
					break;
				}
			}
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_result(dc, op, e2);
			break;
		}

		/* ---- Array building ---- */
		case ZEND_INIT_ARRAY: {
			if (op->op1_type == IS_UNUSED) {
				dc_result(dc, op, "[]");
			} else {
				e1 = dc_operand(dc, op->op1_type, op->op1, op);
				if (op->op2_type != IS_UNUSED) {
					e2 = dc_operand(dc, op->op2_type, op->op2, op);
					snprintf(buf, sizeof(buf), "[%s => %s]", e2, e1);
				} else {
					snprintf(buf, sizeof(buf), "[%s]", e1);
				}
				dc_result(dc, op, buf);
			}
			break;
		}

		case ZEND_ADD_ARRAY_ELEMENT: {
			uint32_t ridx = EX_VAR_TO_NUM(op->result.var);
			char *cur = dc_expr_get(dc, ridx);
			if (!cur) cur = "[]";
			size_t curlen = strlen(cur);
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			if (op->op2_type != IS_UNUSED) {
				e2 = dc_operand(dc, op->op2_type, op->op2, op);
				snprintf(buf, sizeof(buf), "%.*s, %s => %s]",
					(int)(curlen - 1), cur, e2, e1);
			} else {
				snprintf(buf, sizeof(buf), "%.*s, %s]",
					(int)(curlen - 1), cur, e1);
			}
			dc_expr_set(dc, ridx, buf);
			break;
		}

		case ZEND_ADD_ARRAY_UNPACK: {
			uint32_t ridx = EX_VAR_TO_NUM(op->result.var);
			char *cur = dc_expr_get(dc, ridx);
			if (!cur) cur = "[]";
			size_t curlen = strlen(cur);
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "%.*s, ...%s]",
				(int)(curlen - 1), cur, e1);
			dc_expr_set(dc, ridx, buf);
			break;
		}

		/* ---- String rope ---- */
		case ZEND_ROPE_INIT:
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_result(dc, op, e2);
			break;

		case ZEND_ROPE_ADD:
		case ZEND_ROPE_END: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			snprintf(buf, sizeof(buf), "%s . %s", e1, e2);
			dc_result(dc, op, buf);
			break;
		}

		/* ---- Control flow ---- */
		case ZEND_JMP: {
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op1) - ops);
			dc_indent_print(dc, "goto L%04u;", tgt);
			break;
		}

		case ZEND_JMPZ: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			dc_indent_print(dc, "if (!(%s)) goto L%04u;", e1, tgt);
			break;
		}

		case ZEND_JMPNZ: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			dc_indent_print(dc, "if (%s) goto L%04u;", e1, tgt);
			break;
		}

		case ZEND_JMPZ_EX: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			dc_result(dc, op, e1);
			dc_indent_print(dc, "/* &&: if (!%s) goto L%04u */", e1, tgt);
			break;
		}

		case ZEND_JMPNZ_EX: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			dc_result(dc, op, e1);
			dc_indent_print(dc, "/* ||: if (%s) goto L%04u */", e1, tgt);
			break;
		}

		case ZEND_JMP_SET: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			snprintf(buf, sizeof(buf), "%s /* ?:, goto L%04u if truthy */", e1, tgt);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_COALESCE: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t tgt = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			snprintf(buf, sizeof(buf), "%s /* ??, goto L%04u if set */", e1, tgt);
			dc_result(dc, op, buf);
			break;
		}

		/* ---- Foreach ---- */
		case ZEND_FE_RESET_R:
		case ZEND_FE_RESET_RW: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			uint32_t end = (uint32_t)(OP_JMP_ADDR(op, op->op2) - ops);
			dc_indent_print(dc, "/* foreach (%s as ...) [end→L%04u] {", e1, end);
			dc_result(dc, op, e1);
			dc->indent++;
			break;
		}

		case ZEND_FE_FETCH_R:
		case ZEND_FE_FETCH_RW: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "/* foreach value: %s => %s */", e1, e2);
			break;
		}

		/* ---- Unset ---- */
		case ZEND_UNSET_VAR:
		case ZEND_UNSET_CV:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_indent_print(dc, "unset(%s);", e1);
			if (op->op1_type == IS_CV) {
				dc_expr_set(dc, EX_VAR_TO_NUM(op->op1.var), NULL);
			}
			break;

		case ZEND_UNSET_DIM:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "unset(%s[%s]);", e1, e2);
			break;

		case ZEND_UNSET_OBJ:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "unset(%s->%s);", e1, e2);
			break;

		case ZEND_UNSET_STATIC_PROP:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "unset(%s::%s);", e2, e1);
			break;

		/* ---- isset / empty ---- */
		case ZEND_ISSET_ISEMPTY_VAR:
		case ZEND_ISSET_ISEMPTY_CV: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			const char *fn = (op->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";
			snprintf(buf, sizeof(buf), "%s(%s)", fn, e1);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_ISSET_ISEMPTY_DIM_OBJ: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			const char *fn = (op->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";
			snprintf(buf, sizeof(buf), "%s(%s[%s])", fn, e1, e2);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_ISSET_ISEMPTY_PROP_OBJ: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			const char *fn = (op->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";
			snprintf(buf, sizeof(buf), "%s(%s->%s)", fn, e1, e2);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_ISSET_ISEMPTY_STATIC_PROP: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			const char *fn = (op->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";
			snprintf(buf, sizeof(buf), "%s(%s::%s)", fn, e2, e1);
			dc_result(dc, op, buf);
			break;
		}

		case ZEND_ISSET_ISEMPTY_THIS: {
			const char *fn = (op->extended_value & ZEND_ISEMPTY) ? "empty" : "isset";
			snprintf(buf, sizeof(buf), "%s($this)", fn);
			dc_result(dc, op, buf);
			break;
		}

		/* ---- instanceof ---- */
		case ZEND_INSTANCEOF:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			snprintf(buf, sizeof(buf), "(%s instanceof %s)", e1, e2);
			dc_result(dc, op, buf);
			break;

		/* ---- type checks ---- */
		case ZEND_TYPE_CHECK: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			const char *type_fn;
			switch (op->extended_value) {
				case IS_NULL:   type_fn = "is_null";   break;
				case IS_LONG:   type_fn = "is_int";    break;
				case IS_DOUBLE: type_fn = "is_float";  break;
				case IS_STRING: type_fn = "is_string"; break;
				case IS_ARRAY:  type_fn = "is_array";  break;
				case IS_OBJECT: type_fn = "is_object"; break;
				case IS_RESOURCE: type_fn = "is_resource"; break;
				default:        type_fn = "is_bool";   break;
			}
			snprintf(buf, sizeof(buf), "%s(%s)", type_fn, e1);
			dc_result(dc, op, buf);
			break;
		}

		/* ---- built-in intrinsics ---- */
		case ZEND_STRLEN:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "strlen(%s)", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_COUNT:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "count(%s)", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_GET_CLASS:
			if (op->op1_type == IS_UNUSED) {
				dc_result(dc, op, "get_class()");
			} else {
				e1 = dc_operand(dc, op->op1_type, op->op1, op);
				snprintf(buf, sizeof(buf), "get_class(%s)", e1);
				dc_result(dc, op, buf);
			}
			break;

		case ZEND_GET_CALLED_CLASS:
			dc_result(dc, op, "get_called_class()");
			break;

		case ZEND_GET_TYPE:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "gettype(%s)", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_ARRAY_KEY_EXISTS:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			snprintf(buf, sizeof(buf), "array_key_exists(%s, %s)", e1, e2);
			dc_result(dc, op, buf);
			break;

		case ZEND_DEFINED:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "defined(%s)", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_CLONE:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "clone %s", e1);
			dc_result(dc, op, buf);
			break;

		case ZEND_FUNC_NUM_ARGS:
			dc_result(dc, op, "func_num_args()");
			break;

		case ZEND_FUNC_GET_ARGS:
			dc_result(dc, op, "func_get_args()");
			break;

		/* ---- include / eval ---- */
		case ZEND_INCLUDE_OR_EVAL: {
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			const char *inc_kw;
			switch (op->extended_value) {
				case ZEND_INCLUDE:      inc_kw = "include";       break;
				case ZEND_INCLUDE_ONCE: inc_kw = "include_once";  break;
				case ZEND_REQUIRE:      inc_kw = "require";       break;
				case ZEND_REQUIRE_ONCE: inc_kw = "require_once";  break;
				case ZEND_EVAL:         inc_kw = NULL;            break;
				default:                inc_kw = "include";       break;
			}
			if (inc_kw) {
				snprintf(buf, sizeof(buf), "%s %s", inc_kw, e1);
			} else {
				snprintf(buf, sizeof(buf), "eval(%s)", e1);
			}
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "%s;", buf);
			} else {
				dc_result(dc, op, buf);
			}
			break;
		}

		/* ---- generators ---- */
		case ZEND_YIELD: {
			if (op->op1_type == IS_UNUSED) {
				snprintf(buf, sizeof(buf), "yield");
			} else if (op->op2_type == IS_UNUSED) {
				e1 = dc_operand(dc, op->op1_type, op->op1, op);
				snprintf(buf, sizeof(buf), "yield %s", e1);
			} else {
				e1 = dc_operand(dc, op->op1_type, op->op1, op);
				e2 = dc_operand(dc, op->op2_type, op->op2, op);
				snprintf(buf, sizeof(buf), "yield %s => %s", e2, e1);
			}
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "%s;", buf);
			} else {
				dc_result(dc, op, buf);
			}
			break;
		}

		case ZEND_YIELD_FROM:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			snprintf(buf, sizeof(buf), "yield from %s", e1);
			if (op->result_type == IS_UNUSED) {
				dc_indent_print(dc, "%s;", buf);
			} else {
				dc_result(dc, op, buf);
			}
			break;

		case ZEND_GENERATOR_CREATE:
			/* marks the function as a generator; no output needed */
			break;

		/* ---- declarations ---- */
		case ZEND_DECLARE_CLASS:
		case ZEND_DECLARE_CLASS_DELAYED:
			if (op->op1_type == IS_CONST) {
				const zval *zv = RT_CONSTANT(op, op->op1);
				if (Z_TYPE_P(zv) == IS_STRING)
					dc_indent_print(dc, "/* class %s declared */", Z_STRVAL_P(zv));
			}
			break;

		case ZEND_DECLARE_FUNCTION:
			if (op->op1_type == IS_CONST) {
				const zval *zv = RT_CONSTANT(op, op->op1);
				if (Z_TYPE_P(zv) == IS_STRING)
					dc_indent_print(dc, "/* function %s() declared */", Z_STRVAL_P(zv));
			}
			break;

		case ZEND_DECLARE_LAMBDA_FUNCTION:
			dc_indent_print(dc, "/* lambda/closure declared */");
			dc_result(dc, op, "function(...) { ... }");
			break;

		case ZEND_DECLARE_ANON_CLASS:
			dc_indent_print(dc, "/* anonymous class declared */");
			dc_result(dc, op, "new class { ... }");
			break;

		case ZEND_DECLARE_CONST:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "define(%s, %s);", e1, e2);
			break;

		/* ---- parameters ---- */
		case ZEND_RECV:
		case ZEND_RECV_INIT:
		case ZEND_RECV_VARIADIC: {
			if (op->result_type != IS_UNUSED) {
				uint32_t vidx = EX_VAR_TO_NUM(op->result.var);
				char pname[256];
				if (vidx < (uint32_t)oa->last_var) {
					snprintf(pname, sizeof(pname), "$%s",
						ZSTR_VAL(oa->vars[vidx]));
				} else {
					snprintf(pname, sizeof(pname), "$p%u", vidx);
				}
				dc_result(dc, op, pname);
				if (op->opcode == ZEND_RECV_INIT) {
					e2 = dc_operand(dc, op->op2_type, op->op2, op);
					dc_indent_print(dc, "/* param %s = %s */", pname, e2);
				} else if (op->opcode == ZEND_RECV_VARIADIC) {
					dc_indent_print(dc, "/* param ...%s */", pname);
				} else {
					dc_indent_print(dc, "/* param %s */", pname);
				}
			}
			break;
		}

		/* ---- scope / static ---- */
		case ZEND_BIND_GLOBAL:
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "global %s;", e2);
			break;

		case ZEND_BIND_STATIC:
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "static %s;", e2);
			break;

		case ZEND_BIND_LEXICAL:
			e2 = dc_operand(dc, op->op2_type, op->op2, op);
			dc_indent_print(dc, "/* use(%s) */", e2);
			break;

		/* ---- silence operator ---- */
		case ZEND_BEGIN_SILENCE:
			dc_result(dc, op, "@");
			break;

		case ZEND_END_SILENCE:
			break;

		/* ---- match ---- */
		case ZEND_MATCH:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_indent_print(dc, "/* match (%s) { ... } */", e1);
			dc_result(dc, op, dc_xasprintf("match(%s){...}", e1));
			break;

		case ZEND_MATCH_ERROR:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_indent_print(dc, "/* match exhausted for %s → UnhandledMatchError */", e1);
			break;

		/* ---- misc ---- */
		case ZEND_COPY_TMP:
			e1 = dc_operand(dc, op->op1_type, op->op1, op);
			dc_result(dc, op, e1);
			break;

		default: {
			const char *opname = zend_get_opcode_name(op->opcode);
			dc_indent_print(dc, "/* %s (opcode=%u, line=%u) */",
				opname ? opname : "?", op->opcode, op->lineno);
			break;
		}
		} /* switch */

next:
		free(e1); e1 = NULL;
		free(e2); e2 = NULL;
		free(ev); ev = NULL;
	} /* for each op */
}

static void inspector_decompile(FILE *out, const zend_op_array *op_array)
{
	const char *filename =
		op_array->filename ? ZSTR_VAL(op_array->filename) : "(unknown)";

	fprintf(out, "\n/* ===[ DECOMPILED: %s ]=== */\n<?php\n", filename);
	fflush(out);

	dc_state dc;
	memset(&dc, 0, sizeof(dc));
	dc.out      = out;
	dc.op_array = op_array;

	dc_build_jump_map(&dc);
	dc_run(&dc);

	for (int j = 0; j < DC_MAX_VARS; j++) free(dc.temps[j].str);
	free(dc.is_jump_target);

	fprintf(out, "/* ===[ END DECOMPILED: %s ]=== */\n\n", filename);
	fflush(out);
}

/* =========================================================================
 * Core inspection logic — shared by all hook entry points
 * =========================================================================
 *
 * This is the single function that decides what to output for a given
 * op_array.  It is called from three places:
 *
 *   1. zend_accel_load_script() — covers every OPcache path (SHM hit,
 *      file-cache hit, newly compiled+cached).  This is the primary path
 *      and handles "JIT / file-cache only" deployments where the .php
 *      source files do not exist on disk.
 *
 *   2. source_inspector_compile_file() — fallback for when OPcache is not
 *      loaded at all.  When OPcache is present it will have already called
 *      us via path (1); deduplication makes the second call a no-op.
 *
 *   3. source_inspector_compile_string() — eval / assert strings.
 *      These never go through zend_accel_load_script so must be handled
 *      separately; the source string is passed explicitly.
 * ========================================================================= */

ZEND_API void zend_source_inspector_inspect_op_array(zend_op_array *op_array)
{
	if (!op_array) return;

	const char *filename =
		op_array->filename ? ZSTR_VAL(op_array->filename) : "(unknown)";

	/* Emit each file at most once per process */
	if (!inspector_mark_seen(filename)) return;

	FILE *out = inspector_open_output(filename);

	/* Try to read source from the filesystem */
	FILE *src_fp = fopen(filename, "rb");
	if (src_fp) {
		fseek(src_fp, 0, SEEK_END);
		long fsize = ftell(src_fp);
		rewind(src_fp);
		if (fsize > 0) {
			char *src = (char *)malloc((size_t)fsize + 1);
			if (src) {
				size_t nread = fread(src, 1, (size_t)fsize, src_fp);
				src[nread] = '\0';
				fclose(src_fp);
				inspector_output_source(out, filename, src, nread);
				free(src);
				inspector_close_output(out);
				return;
			}
		}
		fclose(src_fp);
	}

	/*
	 * Source not accessible: file-cache-only deployment, Phar, stream
	 * wrapper, or deleted file.  Dump decoded opcodes + decompile.
	 */
	inspector_output_bytecode(out, op_array);
	inspector_decompile(out, op_array);
	inspector_close_output(out);
}

/* =========================================================================
 * compile_file hook — fallback when OPcache is absent
 * =========================================================================
 *
 * When OPcache IS loaded its zend_accel_load_script() patch is the
 * primary inspection point.  This hook is still needed to:
 *   a) Cover the no-OPcache case completely.
 *   b) Provide the filename from file_handle when op_array->filename
 *      is not yet set (rare, but possible for some stream wrappers).
 * Deduplication ensures no double output when both paths fire.
 * ========================================================================= */

static zend_op_array *source_inspector_compile_file(
	zend_file_handle *file_handle, int type)
{
	zend_op_array *op_array =
		zend_source_inspector_orig_compile(file_handle, type);

	if (!op_array) return NULL;

	/* If op_array has no filename yet, set a fallback before inspecting. */
	if (!op_array->filename && file_handle->filename) {
		op_array->filename = zend_string_copy(file_handle->filename);
	}

	zend_source_inspector_inspect_op_array(op_array);
	return op_array;
}

/* =========================================================================
 * compile_string hook  (catches eval / preg_replace /e / assert strings)
 * ========================================================================= */

static zend_op_array *source_inspector_compile_string(
	zend_string *source_string, const char *filename,
	zend_compile_position position)
{
	zend_op_array *op_array =
		zend_source_inspector_orig_compile_string(source_string, filename, position);

	if (!op_array) {
		return NULL;
	}

	/*
	 * For eval'd strings the source is right here in `source_string`.
	 * Output it, then dump bytecode so we see what the obfuscator's
	 * runtime payload compiled to.
	 */
	const char *display_name = filename ? filename : "(eval)";
	FILE *out = inspector_open_output(display_name);

	fprintf(out, "\n/* ===[ EVAL SOURCE: %s ]=== */\n", display_name);
	if (ZSTR_LEN(source_string) > 0) {
		fwrite(ZSTR_VAL(source_string), 1, ZSTR_LEN(source_string), out);
		if (ZSTR_VAL(source_string)[ZSTR_LEN(source_string) - 1] != '\n')
			fputc('\n', out);
	}
	fprintf(out, "/* ===[ END EVAL SOURCE: %s ]=== */\n", display_name);

	inspector_output_bytecode(out, op_array);
	inspector_decompile(out, op_array);

	inspector_close_output(out);
	return op_array;
}

/* =========================================================================
 * Hook installation / removal
 * ========================================================================= */

ZEND_API void zend_source_inspector_register_ini(void)
{
	/* zend_register_ini_entries() looks up the module in module_registry,
	 * but INSPECTOR_MODULE_NUMBER (-42) is not a real module entry.
	 * Call the _ex variant directly to bypass that lookup and register
	 * straight into registered_zend_ini_directives (the persistent table)
	 * so that php_init_config() / -d processing can find our key. */
	zend_register_ini_entries_ex(ini_entries, INSPECTOR_MODULE_NUMBER, MODULE_PERSISTENT);
}

ZEND_API void zend_source_inspector_install(void)
{
	/* zend_register_ini_entries() requires the module in module_registry.
	 * Use _ex() directly; by the time install() is called (after
	 * zend_startup_extensions()), php_init_config() has already populated
	 * configuration_hash, so our on_modify handler fires for -d/php.ini values. */
	zend_register_ini_entries_ex(ini_entries, INSPECTOR_MODULE_NUMBER, MODULE_PERSISTENT);

	if (zend_compile_file != source_inspector_compile_file) {
		zend_source_inspector_orig_compile = zend_compile_file;
		zend_compile_file = source_inspector_compile_file;
	}
	if (zend_compile_string != source_inspector_compile_string) {
		zend_source_inspector_orig_compile_string = zend_compile_string;
		zend_compile_string = source_inspector_compile_string;
	}
}

ZEND_API void zend_source_inspector_uninstall(void)
{
	zend_unregister_ini_entries_ex(INSPECTOR_MODULE_NUMBER, MODULE_PERSISTENT);
	free(inspector_output_dir_cfg);
	inspector_output_dir_cfg = NULL;

	if (zend_compile_file == source_inspector_compile_file &&
	    zend_source_inspector_orig_compile != NULL) {
		zend_compile_file = zend_source_inspector_orig_compile;
		zend_source_inspector_orig_compile = NULL;
	}
	if (zend_compile_string == source_inspector_compile_string &&
	    zend_source_inspector_orig_compile_string != NULL) {
		zend_compile_string = zend_source_inspector_orig_compile_string;
		zend_source_inspector_orig_compile_string = NULL;
	}
}
