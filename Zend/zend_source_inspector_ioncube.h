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

END_EXTERN_C()

#endif /* _WIN32 */

#endif /* ZEND_SOURCE_INSPECTOR_IONCUBE_H */
