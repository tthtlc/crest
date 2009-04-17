// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include <assert.h>
#include <fstream>
#include <string>
#include <vector>

#include "base/symbolic_interpreter.h"
#include "libcrest/crest.h"

using std::vector;
using namespace crest;

// The symbolic interpreter.
static SymbolicInterpreter* SI;

// Have we read an input yet?  Until we have, generate only the
// minimal instrumentation necessary to track which branches were
// reached by the execution path.
static int pre_symbolic;

// Tables for converting from operators defined in libcrest/crest.h to
// those defined in base/basic_types.h.
static const int kOpTable[] =
  { // binary arithmetic
    ops::ADD, ops::SUBTRACT, ops::MULTIPLY, ops::CONCRETE, ops::CONCRETE,
    // binary bitwise operators
    ops::CONCRETE, ops::CONCRETE, ops::CONCRETE, ops::CONCRETE, ops::CONCRETE,
    // binary logical operators
    ops::CONCRETE, ops::CONCRETE,
    // binary comparison
    ops::EQ, ops::NEQ, ops::GT, ops::LE, ops::LT, ops::GE,
    // unhandled binary operators
    ops::CONCRETE,
    // unary operators
    ops::NEGATE, ops::BITWISE_NOT, ops::LOGICAL_NOT
  };


static void __CrestAtExit();


#if 0  // malloc hooks do not work under Mac OS X.

// CREST hooks for malloc functions.
static void crest_init_hook(void);
static void* crest_malloc_hook(size_t, const void*);
static void* crest_realloc_hook(void*, size_t, const void*);
static void crest_free_hook(void*, const void*);
static void* crest_memalign_hook(size_t, size_t, const void*);

// Original malloc hooks.
static void* (*orig_malloc_hook)(size_t, const void*);
static void* (*orig_realloc_hook)(void*, size_t, const void*);
static void (*orig_free_hook)(void*, const void*);
static void* (*orig_memalign_hook)(size_t, size_t, const void*);

// Make sure CREST hooks are installed right after malloc is initialzed.
void (*__malloc_initialize_hook) (void) = crest_init_hook;

// Save original malloc hooks.
static inline void save_original_hooks(void) {
  orig_malloc_hook = __malloc_hook;
  orig_realloc_hook = __realloc_hook;
  orig_free_hook = __free_hook;
  orig_memalign_hook = __memalign_hook;
}

// Install CREST hooks for malloc functions.
static inline void install_crest_hooks(void) {
  __malloc_hook = crest_malloc_hook;
  __realloc_hook = crest_realloc_hook;
  __free_hook = crest_free_hook;
  __memalign_hook = crest_memalign_hook;
}

// Restore original hooks for malloc functions.
static inline void restore_original_hooks(void) {
  __malloc_hook = orig_malloc_hook;
  __realloc_hook = orig_realloc_hook;
  __free_hook = orig_free_hook;
  __memalign_hook = orig_memalign_hook;
}

// After malloc initialization, save original hooks and install CREST hooks.
static void crest_init_hook(void) {
  save_original_hooks();
  install_crest_hooks();
}

static void* crest_malloc_hook (size_t size, const void* caller) {
  restore_original_hooks();
  void* result = malloc (size);
  // TODO: Record allocation.
  save_original_hooks();
  install_crest_hooks();
  return result;
}

static void* crest_realloc_hook(void* p, size_t size, const void* caller) {
  restore_original_hooks();
  void* result = realloc(p, size);
  // TODO: Record free and allocation.
  save_original_hooks();
  install_crest_hooks();
  return result;
}

static void crest_free_hook (void* p, const void* caller) {
  restore_original_hooks();
  free(p);
  // Record free.
  save_original_hooks();
  install_crest_hooks();
}

static void* crest_memalign_hook(size_t align, size_t size, const void* caller) {
  restore_original_hooks();
  void* result = memalign(align, size);
  // Record allocation.
  save_original_hooks();
  install_crest_hooks();
  return result;
}

#endif


void __CrestInit(__CREST_ID id) {
  /* read the input */
  vector<value_t> input;
  std::ifstream in("input");
  value_t val;
  while (in >> val) {
    input.push_back(val);
  }
  in.close();

  SI = new SymbolicInterpreter(input);

  pre_symbolic = 1;

  assert(!atexit(__CrestAtExit));
}


void __CrestAtExit() {
  const SymbolicExecution& ex = SI->execution();

  /* Write the execution out to file 'szd_execution'. */
  string buff;
  buff.reserve(1<<26);
  ex.Serialize(&buff);
  std::ofstream out("szd_execution", std::ios::out | std::ios::binary);
  out.write(buff.data(), buff.size());
  assert(!out.fail());
  out.close();
}


//
// Instrumentation functions.
//

void __CrestRegGlobal(__CREST_ID id, __CREST_ADDR addr, size_t size) {
  // TODO: Record as allocation.
}


void __CrestLoad(__CREST_ID id, __CREST_ADDR addr,
                 __CREST_TYPE ty, __CREST_VALUE val) {
  if (!pre_symbolic)
    SI->Load(id, addr, val);
}


void __CrestLoadAggr(__CREST_ID id, __CREST_ADDR addr,
                     __CREST_TYPE ty, size_t size) {
  // TODO: Load an aggregate value -- i.e. a struct.  No operations
  // will be performed on it except possibly eventually storing it.
}


void __CrestStore(__CREST_ID id, __CREST_ADDR addr) {
  if (!pre_symbolic)
    SI->Store(id, addr);
}


void __CrestClearStack(__CREST_ID id) {
  if (!pre_symbolic)
    SI->ClearStack(id);
}


void __CrestApply1(__CREST_ID id, __CREST_OP op,
                   __CREST_TYPE ty, __CREST_VALUE val) {
  assert((op >= __CREST_NEGATE) && (op <= __CREST_L_NOT));

  if (!pre_symbolic)
    SI->ApplyUnaryOp(id, static_cast<unary_op_t>(kOpTable[op]), val);
}


void __CrestApply2(__CREST_ID id, __CREST_OP op,
                   __CREST_TYPE ty, __CREST_VALUE val) {
  assert((op >= __CREST_ADD) && (op <= __CREST_CONCRETE));

  if (pre_symbolic)
    return;

  if ((op >= __CREST_ADD) && (op <= __CREST_L_OR)) {
    SI->ApplyBinaryOp(id, static_cast<binary_op_t>(kOpTable[op]), val);
  } else {
    SI->ApplyCompareOp(id, static_cast<compare_op_t>(kOpTable[op]), val);
  }
}


void __CrestPtrApply2(__CREST_ID id, __CREST_OP op,
                      size_t size, __CREST_VALUE val) {
  // TODO:
}

void __CrestBranch(__CREST_ID id, __CREST_BRANCH_ID bid, __CREST_BOOL b) {
  if (pre_symbolic) {
    // Precede the branch with a fake (concrete) load.
    SI->Load(id, 0, b);
  }

  SI->Branch(id, bid, static_cast<bool>(b));
}


void __CrestCall(__CREST_ID id, __CREST_FUNCTION_ID fid) {
  SI->Call(id, fid);
}


void __CrestReturn(__CREST_ID id) {
  SI->Return(id);
}


void __CrestHandleReturn(__CREST_ID id, __CREST_TYPE ty, __CREST_VALUE val) {
  if (!pre_symbolic)
    SI->HandleReturn(id, val);
}


//
// Symbolic input functions.
//

void __CrestUChar(unsigned char* x) {
  pre_symbolic = 0;
  *x = (unsigned char)SI->NewInput(types::U_CHAR, (addr_t)x);
}

void __CrestUShort(unsigned short* x) {
  pre_symbolic = 0;
  *x = (unsigned short)SI->NewInput(types::U_SHORT, (addr_t)x);
}

void __CrestUInt(unsigned int* x) {
  pre_symbolic = 0;
  *x = (unsigned int)SI->NewInput(types::U_INT, (addr_t)x);
}

void __CrestChar(char* x) {
  pre_symbolic = 0;
  *x = (char)SI->NewInput(types::CHAR, (addr_t)x);
}

void __CrestShort(short* x) {
  pre_symbolic = 0;
  *x = (short)SI->NewInput(types::SHORT, (addr_t)x);
}

void __CrestInt(int* x) {
  pre_symbolic = 0;
  *x = (int)SI->NewInput(types::INT, (addr_t)x);
}
