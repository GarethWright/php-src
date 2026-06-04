/*
   +----------------------------------------------------------------------+
   | Zend Engine - PHP Source Inspector: IonCube 15.x bytecode decoder    |
   +----------------------------------------------------------------------+
   | Decodes IonCube 15.x VM bytecode from live process memory using the  |
   | CBC-XOR cipher and double-indirection instruction format discovered   |
   | by reverse-engineering the IonCube loader DLL.                       |
   | SPDX-License-Identifier: BSD-3-Clause                                |
   +----------------------------------------------------------------------+
*/
#ifndef ZEND_SOURCE_INSPECTOR_IONCUBE_H
#define ZEND_SOURCE_INSPECTOR_IONCUBE_H

#ifdef _WIN32

#include <stdio.h>
#include "zend_compile.h"

BEGIN_EXTERN_C()

/*
 * Decode IonCube VM bytecode for a stub op_array and write the decoded
 * instruction sequence (with best-effort PHP reconstruction) to `out`.
 *
 * Layout of IonCube 15.x BC (per method):
 *   reserved[3] → class dispatch slot (stride 0xE0)
 *   slot+0x88   → method descriptor (stride 0x80)
 *   desc+0x08   → bc_ptr (96-byte blocks in a linked list)
 *
 * Each 96-byte block:
 *   +0x00 [32B]: CBC-XOR encrypted instruction operands
 *   +0x20 [32B]: instruction pointer array:
 *                  [0] type-A operand ctx ptr
 *                  [1] main operand data ptr → 8B heap ptr + 3×8B DLL handlers
 *                  [2] next block linked-list ptr
 *                  [3] NULL
 *   +0x40 [32B]: 4×8B DLL dispatch handler ptrs (for type dispatch)
 *
 * CBC-XOR cipher: dec = enc XOR key; key_next = enc (16-bit words)
 *   Initial key: 0x23B1 (hardcoded in IonCube DLL at offset 0x8ECB5)
 *   Each slot[1] always ends with 0x0000 → key resets to 0x0000 per block
 */
void zend_source_inspector_decode_ioncube(
    FILE *out,
    const zend_op_array *op_array);

/* =========================================================================
 * Dynamic execution tracer API
 *
 * These functions implement a runtime tracer that hooks PHP's object property
 * handlers and zend_execute_internal to observe what IonCube-encoded methods
 * actually do, producing PHP-level reconstructions without needing to know
 * IonCube's opcode table.
 *
 * Usage:
 *   1. Call ic_tracer_global_init() once at startup.
 *   2. Call ic_install_class_trace(ce) for each IonCube-encoded class.
 *   3. Call ic_trace_begin(op_array) when entering an IC stub method.
 *   4. Let IonCube execute the method (it calls read_property etc.).
 *   5. Call ic_trace_end(out) to emit the reconstructed PHP to `out`.
 *   6. Call ic_tracer_global_shutdown() at RSHUTDOWN.
 * ========================================================================= */

/*
 * Initialise tracer global state.  Must be called before any other tracer
 * function.  Safe to call multiple times (idempotent).
 */
void ic_tracer_global_init(void);

/*
 * Release all tracer global state (property handler backups etc.).
 * Must be called at RSHUTDOWN/MSHUTDOWN.
 */
void ic_tracer_global_shutdown(void);

/*
 * Install property-read/write tracing hooks on the object handlers for `ce`.
 * Saves the original handlers so they can be restored and still called.
 * Safe to call multiple times for the same class (idempotent).
 */
void ic_install_class_trace(zend_class_entry *ce);

/*
 * Mark the start of tracing for one IonCube method call.
 * Must be called just before handing control to IonCube's executor.
 * `op_array` is the stub op_array (last==0) that describes the method.
 * Re-entrant: pushes a frame onto the internal trace stack (max depth 32).
 */
void ic_trace_begin(const zend_op_array *op_array);

/*
 * Mark the end of tracing for the innermost active trace frame.
 * Emits the collected operations as reconstructed PHP to `out`.
 * Pops the top of the trace stack.
 */
void ic_trace_end(FILE *out);

/*
 * Called from the zend_execute_internal hook: log a built-in function call
 * that occurred from within IonCube-encoded code.
 * `execute_data` is the internal call frame; `return_value` may be NULL.
 */
void ic_trace_internal_call(
    zend_execute_data *execute_data,
    zval              *return_value);

END_EXTERN_C()

#endif /* _WIN32 */

#endif /* ZEND_SOURCE_INSPECTOR_IONCUBE_H */
