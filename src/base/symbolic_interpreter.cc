// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include <algorithm>
#include <assert.h>
#include <stdio.h>
#include <utility>
#include <vector>

#include "base/symbolic_interpreter.h"
#include "base/symbolic_object.h"
#include "base/yices_solver.h"
#include "base/deref_expression.h"
#include "base/basic_expression.h"

using std::make_pair;
using std::swap;
using std::vector;

#ifdef DEBUG
#define IFDEBUG(x) x
#else
#define IFDEBUG(x)
#endif

#define IFDEBUG2(x)

namespace crest {

typedef map<addr_t,SymbolicExpr*>::const_iterator ConstMemIt;

SymbolicInterpreter::SymbolicInterpreter()
  : ex_(true), num_inputs_(0) {
  stack_.reserve(16);
}

SymbolicInterpreter::SymbolicInterpreter(const vector<value_t>& input)
  : ex_(true) {
  stack_.reserve(16);
  ex_.mutable_inputs()->assign(input.begin(), input.end());
}


void SymbolicInterpreter::DumpMemory() {
  fprintf(stderr, "\n");
  mem_.Dump();
  obj_tracker_.Dump();

  for (size_t i = 0; i < stack_.size(); i++) {
    string s;
    if (stack_[i].expr) {
      stack_[i].expr->AppendToString(&s);
    }
    fprintf(stderr, "s%zu (%d): %lld [ %s ]\n", i,
            stack_[i].ty, stack_[i].concrete, s.c_str());
  }

  fprintf(stderr, "\n");
}


void SymbolicInterpreter::ClearStack(id_t id) {
  IFDEBUG(fprintf(stderr, "clear\n"));
  vector<StackElem>::const_iterator it;
  for (it = stack_.begin(); it != stack_.end(); ++it) {
    delete it->expr;
  }
  stack_.clear();
  return_value_ = false;
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Load(id_t id, addr_t addr, type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "load %lu %lld\n", addr, value));

  SymbolicObject* obj = obj_tracker_.find(addr);
  SymbolicExpr* e = NULL;
  if (obj == NULL) {
    // Load from main memory.
    e = mem_.read(addr, ty, value);
  } else {
    // Load from a symbolic object.
    e = obj->read(addr, ty, value);
  }

  IFDEBUG2({
      if (e) {
        string s;
        e->AppendToString(&s);
        fprintf(stderr, "load %lu %lld : %s\n", addr, value, s.c_str());
      }})

  PushSymbolic(e, ty, value);

  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Deref(id_t id, addr_t addr, type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "deref %lu %lld\n", addr, value));
  assert(stack_.size() > 0);

  SymbolicExpr* e = NULL;
  SymbolicObject* obj = obj_tracker_.find(addr);

  // Is this a symbolic dereference?
  const StackElem& se = stack_.back();
  if (obj && se.expr && !se.expr->IsConcrete()) {
    e = SymbolicExpr::NewDerefExpr(ty, value, *obj, se.expr);
  } else {
    delete se.expr;
  }
  stack_.pop_back();

  // If this is not a symbolic dereference, do a normal load.
  if (e == NULL) {
    if (obj == NULL) {
      // Load from main memory.
     e = mem_.read(addr, ty, value);
    } else {
      // Load from a symbolic object.
      e = obj->read(addr, ty, value);
    }
  }

  IFDEBUG2({
      if (e) {
        string s;
        e->AppendToString(&s);
        fprintf(stderr, "deref %lu %lld : %s\n", addr, value, s.c_str());
      }})


  PushSymbolic(e, ty, value);

  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Store(id_t id, addr_t addr) {
  IFDEBUG(fprintf(stderr, "store %lu\n", addr));
  assert(stack_.size() > 0);

  const StackElem& se = stack_.back();

  IFDEBUG2({
      if (se.expr) {
        string s;
        se.expr->AppendToString(&s);
        fprintf(stderr, "store %lu : %s\n", addr, s.c_str());
      }})

  // Is this a write to an object?
  SymbolicObject* obj = obj_tracker_.find(addr);
  if (obj != NULL) {
    if (se.expr && !se.expr->IsConcrete()) {
      // Transfers ownership of se.expr.
      obj->write(NULL, addr, se.expr);
    } else {
      obj->concretize(NULL, addr, sizeOfType(se.ty, se.concrete));
    }
  } else {
    // Write to untracked region/object.
    if (se.expr && !se.expr->IsConcrete()) {
      mem_.write(addr, se.expr);
    } else {
      delete se.expr;
      mem_.concretize(addr, sizeOfType(se.ty, se.concrete));
    }
  }

  stack_.pop_back();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Write(id_t id, addr_t addr) {
  IFDEBUG(fprintf(stderr, "write %lu\n", addr));
  assert(stack_.size() > 1);

  const StackElem& dest = *(stack_.rbegin()+1);
  const StackElem& val = stack_.back();

  IFDEBUG2({
      if (val.expr) {
        string s;
        val.expr->AppendToString(&s);
        fprintf(stderr, "store %lu : %s\n", addr, s.c_str());
      }})

  // Is this a write to an object.
  SymbolicObject* obj = obj_tracker_.find(addr);
  if (obj != NULL) {
    if (val.expr && !val.expr->IsConcrete()) {
      // Transfers ownership of dest.expr and val.expr.
      obj->write(dest.expr, addr, val.expr);
    } else {
      obj->concretize(dest.expr, addr, sizeOfType(val.ty, val.concrete));
    }
  } else {
    // Normal store -- may be concretizing a symbolic write to an
    // untracked region/object.
    if (val.expr && !val.expr->IsConcrete()) {
      mem_.write(addr, val.expr);
    } else {
      mem_.concretize(addr, sizeOfType(val.ty, val.concrete));
      delete val.expr;
    }
  }

  stack_.pop_back();
  stack_.pop_back();

  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyUnaryOp(id_t id, unary_op_t op,
                                       type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "apply1 %d %lld\n", op, value));
  assert(stack_.size() >= 1);
  StackElem& se = stack_.back();

  if (se.expr)
    se.expr = SymbolicExpr::NewUnaryExpr(ty, value, op, se.expr);

  se.ty = ty;
  se.concrete = value;
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyBinaryOp(id_t id, binary_op_t op,
                                        type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "apply2 %d %lld\n", op, value));
  assert(stack_.size() >= 2);
  StackElem& a = *(stack_.rbegin()+1);
  StackElem& b = stack_.back();

  if (a.expr) {
    if (b.expr == NULL) {
      b.expr = SymbolicExpr::NewConcreteExpr(b.ty, b.concrete);
    }
    a.expr = SymbolicExpr::NewBinaryExpr(ty, value, op, a.expr, b.expr);
  } else if (b.expr) {
    a.expr = SymbolicExpr::NewConcreteExpr(a.ty, a.concrete);
    a.expr = SymbolicExpr::NewBinaryExpr(ty, value, op, a.expr, b.expr);
  }

  a.concrete = value;
  a.ty = ty;

  stack_.pop_back();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ScaleUpBy(bool isSigned, size_t size) {
  assert(stack_.size() >= 1);
  StackElem& b = stack_.back();

  unary_op_t cast = isSigned ? ops::SIGNED_CAST : ops::UNSIGNED_CAST;
  type_t ty = isSigned ? types::LONG : types::U_LONG;

  // If necessary, adjust the symbolic value on the stack.
  if (b.expr) {
    // Cast b to be the same size as a signed/unsigned long.
    if (b.expr->size() != kSizeOfType[ty]) {
      b.expr = SymbolicExpr::NewUnaryExpr(ty, b.concrete, cast, b.expr);
    }

    // Multiply b by size
    b.expr = SymbolicExpr::NewBinaryExpr(ty, b.concrete * size,
                                         ops::MULTIPLY, b.expr, size);
  }

  // Adjust the concrete value/type on the stack.
  b.concrete *= size;
  b.ty = ty;
}


void SymbolicInterpreter::ApplyBinPtrOp(id_t id, pointer_op_t op,
                                        size_t size, value_t value) {
  IFDEBUG(fprintf(stderr, "apply2ptr %d(%zu) %lld\n", op, size, value));
  assert(stack_.size() >= 2);
  StackElem& a = *(stack_.rbegin()+1);
  StackElem& b = stack_.back();

  type_t ty = (op == ops::SUBTRACT_PP) ? types::LONG : types::U_LONG;

  if (a.expr || b.expr) {
    // If operation is a pointer-int op, then scale b.
    if ((op != ops::SUBTRACT_PP) && (size > 1)) {
      bool isSigned = ((op == ops::S_ADD_PI) || (op == ops::S_SUBTRACT_PI));
      ScaleUpBy(isSigned, size);
    }

    // Apply the corresponding binary operation.
    if ((op == ops::ADD_PI) || (op == ops::S_ADD_PI)) {
      ApplyBinaryOp(-1, ops::ADD, ty,
                    static_cast<unsigned long>(a.concrete + b.concrete));
    } else {
      ApplyBinaryOp(-1, ops::SUBTRACT, ty,
                    static_cast<unsigned long>(a.concrete - b.concrete));
    }

    // If the operation is pointer-pointer subtraction, scale the result.
    if ((op == ops::SUBTRACT_PP) && (size > 1)) {
      // Currently only works for powers of 2.
      size_t log2 = 0;
      while ((size & 1) == 0) {
        log2++;
        size >>= 1;
      }
      assert(size == 1);

      // TODO: Invert the remainder (module the correct power of two),
      // so that we can use multiplication instead of division.

      a.expr = SymbolicExpr::NewBinaryExpr(ty, value, ops::S_SHIFT_R, a.expr, log2);
    }

  } else {
    // The operation is concrete, so just pop the stack.
    stack_.pop_back();
  }

  a.concrete = value;
  a.ty = ty;
  // Stack has already been popped.
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyCompareOp(id_t id, compare_op_t op,
                                         type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "compare2 %d %lld\n", op, value));
  assert(stack_.size() >= 2);
  StackElem& a = *(stack_.rbegin()+1);
  StackElem& b = stack_.back();

  if (a.expr) {
    if (b.expr == NULL) {
      b.expr = SymbolicExpr::NewConcreteExpr(b.ty, b.concrete);
    }
    a.expr = SymbolicExpr::NewCompareExpr(ty, value, op, a.expr, b.expr);
  } else if (b.expr) {
    a.expr = SymbolicExpr::NewConcreteExpr(a.ty, a.concrete);
    a.expr = SymbolicExpr::NewCompareExpr(ty, value, op, a.expr, b.expr);
  }

  a.concrete = value;
  a.ty = ty;

  stack_.pop_back();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Call(id_t id, function_id_t fid) {
  ex_.mutable_path()->Push(kCallId);
}


void SymbolicInterpreter::Return(id_t id) {
  ex_.mutable_path()->Push(kReturnId);

  // There is either exactly one value on the stack -- the current function's
  // return value -- or the stack is empty.
  assert(stack_.size() <= 1);

  return_value_ = (stack_.size() == 1);
}


void SymbolicInterpreter::HandleReturn(id_t id, type_t ty, value_t value) {
  if (return_value_) {
    // We just returned from an instrumented function, so the stack
    // contains a single element -- the (possibly symbolic) return value.
    assert(stack_.size() == 1);
    return_value_ = false;
  } else {
    // We just returned from an uninstrumented function, so the stack
    // still contains the arguments to that function.  Thus, we clear
    // the stack and push the concrete value that was returned.
    ClearStack(-1);
    PushConcrete(ty, value);
  }
}


void SymbolicInterpreter::Branch(id_t id, branch_id_t bid, bool pred_value) {
  IFDEBUG(fprintf(stderr, "branch %d %d\n", bid, pred_value));
  assert(stack_.size() == 1);
  StackElem& se = stack_.back();

  if (se.expr) {
    if (se.expr->CastCompareExpr()) {
      // If necessary, negate the expression.
      if (!pred_value) {
        se.expr = SymbolicExpr::NewUnaryExpr(types::INT, !pred_value,
                                             ops::LOGICAL_NOT, se.expr);
      }

    } else {
      // Need to create a comparison.
      if (pred_value) {
        SymbolicExpr* zero = SymbolicExpr::NewConcreteExpr(se.expr->size(), 0);
        se.expr = SymbolicExpr::NewCompareExpr(types::INT, 1,
                                               ops::NEQ, se.expr, zero);
      } else {
        SymbolicExpr* zero = SymbolicExpr::NewConcreteExpr(se.expr->size(), 0);
        se.expr = SymbolicExpr::NewCompareExpr(types::INT, 1,
                                               ops::EQ, se.expr, zero);
      }
    }
  }

  ex_.mutable_path()->Push(bid, se.expr);

  stack_.pop_back();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Alloc(id_t id, addr_t addr, size_t size) {
  obj_tracker_.add(addr, size);
}


void SymbolicInterpreter::Free(id_t id, addr_t addr) {
  obj_tracker_.remove(addr);
}


value_t SymbolicInterpreter::NewInput(type_t ty, addr_t addr) {
  assert(ty != types::STRUCT);
  ex_.mutable_vars()->insert(make_pair(num_inputs_, ty));

  // Size and initial, concrete value.
  size_t size = kSizeOfType[ty];
  value_t val = 0;
  if (num_inputs_ < ex_.inputs().size()) {
    val = ex_.inputs()[num_inputs_];
  } else {
    // New inputs are initially zero.  (Could randomize instead.)
    ex_.mutable_inputs()->push_back(0);
  }

  // Is this a write to an object?
  SymbolicObject* obj = obj_tracker_.find(addr);
  if (obj != NULL) {
    obj->write(NULL, addr, new BasicExpr(size, val, num_inputs_));
  } else {
    // Write to untracked region/object.
    mem_.write(addr, new BasicExpr(size, val, num_inputs_));
  }

  num_inputs_++;
  return val;
}


void SymbolicInterpreter::PushConcrete(type_t ty, value_t value) {
  PushSymbolic(NULL, ty, value);
}


void SymbolicInterpreter::PushSymbolic(SymbolicExpr* expr,
                                       type_t ty,
                                       value_t value) {
  stack_.push_back(StackElem());
  StackElem& se = stack_.back();
  se.expr = expr;
  se.ty = ty;
  se.concrete = value;
}


size_t SymbolicInterpreter::sizeOfType(type_t ty, value_t val) {
  if (ty != types::STRUCT) {
    return kSizeOfType[ty];
  } else {
    // For structs, the "concrete value" is the size of the struct.
    return static_cast<size_t>(val);
  }
}

}  // namespace crest
