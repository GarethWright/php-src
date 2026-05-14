/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source/Bytecode Inspector                          |
   +----------------------------------------------------------------------+
   | This source file is subject to the Modified BSD License that is      |
   | bundled with this package in the file LICENSE.                       |
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/

#ifndef ZEND_SOURCE_INSPECTOR_H
#define ZEND_SOURCE_INSPECTOR_H

#include "zend_compile.h"

BEGIN_EXTERN_C()

/* Saved pointer to the previous zend_compile_file handler (may be OPcache's) */
extern ZEND_API zend_op_array *(*zend_source_inspector_orig_compile)(
	zend_file_handle *file_handle, int type);

/* Saved pointer to the previous zend_compile_string handler (covers eval) */
extern ZEND_API zend_op_array *(*zend_source_inspector_orig_compile_string)(
	zend_string *source_string, const char *filename,
	zend_compile_position position);

/*
 * Core inspection function.  Outputs source or bytecode+decompile for one
 * op_array, then marks the filename as seen so subsequent calls for the
 * same file (cache hits, preloads, repeated includes) are silent.
 *
 * Called directly by the patched zend_accel_load_script() in OPcache —
 * that is the primary path covering SHM cache hits, file-cache hits, and
 * newly compiled scripts in one place.  The compile_file hook calls it
 * as a fallback for the no-OPcache case; deduplication makes it a no-op
 * when OPcache already fired.
 */
ZEND_API void zend_source_inspector_inspect_op_array(zend_op_array *op_array);

/*
 * Install the source/bytecode inspector hooks (compile_file + compile_string).
 * Call after all Zend extensions have been started (i.e. after
 * zend_startup_extensions()) so that OPcache's persistent_compile_file
 * is already in place and our wrapper sits on top of it.
 */
ZEND_API void zend_source_inspector_install(void);

/*
 * Remove the hook and restore the previous compile function pointer.
 */
ZEND_API void zend_source_inspector_uninstall(void);

END_EXTERN_C()

#endif /* ZEND_SOURCE_INSPECTOR_H */
