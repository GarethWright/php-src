/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source Inspector: IonCube memory scanner           |
   +----------------------------------------------------------------------+
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/

#ifndef ZEND_SOURCE_INSPECTOR_MEMSCAN_H
#define ZEND_SOURCE_INSPECTOR_MEMSCAN_H

#ifdef _WIN32

#include <stdio.h>
#include "zend_compile.h"

BEGIN_EXTERN_C()

/*
 * Check if `len` bytes starting at `ptr` are readable (committed, not guard).
 */
bool memscan_is_readable(const void *ptr, size_t len);

/*
 * Scan op_array->reserved[] for non-NULL values and dump the memory
 * regions they point to.  out must be an open FILE*.
 * Used to find IonCube's internal bytecode pointer stored in a reserved slot.
 */
void zend_source_inspector_memscan_op_array(
	const zend_op_array *op_array, FILE *out);

/*
 * Walk all committed private pages in the current process and report
 * regions that look like IonCube's internal bytecode or dispatch tables
 * (high PHP-string density or high pointer density).
 */
void zend_source_inspector_memscan_heap(FILE *out);

END_EXTERN_C()

#endif /* _WIN32 */

#endif /* ZEND_SOURCE_INSPECTOR_MEMSCAN_H */
