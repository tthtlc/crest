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
  if (obj == NULL) {
    // Load from main memory.
    PushSymbolic(mem_.read(addr, ty, value), ty, value);
  } else {
    // Load from a symbolic object.
    PushSymbolic(obj->read(addr, ty, value), ty, value);
  }

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
    // TODO: Set e to new expression representing dereference.
	// e will have op_type as DEREF and node type as NONLINEAR
    // e = new SymbolicDeref(new SymbolicObject(obj), ty, se.expr);
	  e = new DerefExpr(se.expr, obj, ty, value);
	  // Add the new symbolic object, address and type to e
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

  PushSymbolic(e, ty, value);

  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Store(id_t id, addr_t addr) {
  IFDEBUG(fprintf(stderr, "store %lu\n", addr));
  assert(stack_.size() > 0);

  const StackElem& se = stack_.back();

  // Is this a write to an object?
  SymbolicObject* obj = obj_tracker_.find(addr);
  if (obj != NULL) {
    // Transfers ownership of se.expr.
    obj->write(NULL, addr, se.expr, se.ty, se.concrete);
  } else {
    // Write to untracked region/object.
    if (se.expr && !se.expr->IsConcrete()) {
      mem_.write(addr, se.ty, se.expr);
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

  // Is this a write to an object.
  SymbolicObject* obj = obj_tracker_.find(addr);
  if (obj != NULL) {
    // Transfers ownership of dest.expr and val.expr.
    obj->write(dest.expr, addr, val.expr, val.ty, val.concrete);
  } else {
    // Normal store -- may be concretizing a symbolic write to an
    // untracked region/object.
    if (val.expr && !val.expr->IsConcrete()) {
      mem_.write(addr, val.ty, val.expr);
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


void SymbolicInterpreter::ApplyBinPtrOp(id_t id, binary_op_t op,
                                        size_t size, value_t value) {
  // TODO: Implement this.
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

  // If necessary, negate the expression.
  if (se.expr && !pred_value) {
    se.expr = SymbolicExpr::NewUnaryExpr(types::INT, !pred_value,
                                         ops::LOGICAL_NOT, se.expr);
  }

  ex_.mutable_path()->Push(bid, se.expr);

  stack_.pop_back();
  IFDEBUG(DumpMemory());
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

  mem_.write(addr, ty, new BasicExpr(size, val, num_inputs_));

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