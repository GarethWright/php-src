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

/*
 * Install the source/bytecode inspector hook.
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
