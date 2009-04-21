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
  : pred_(NULL), ex_(true), num_inputs_(0) {
  stack_.reserve(16);
}

SymbolicInterpreter::SymbolicInterpreter(const vector<value_t>& input)
  : pred_(NULL), ex_(true) {
  stack_.reserve(16);
  ex_.mutable_inputs()->assign(input.begin(), input.end());
}


// void SymbolicInterpreter::DumpMemory() {
//   for (ConstMemIt i = mem_.begin(); i != mem_.end(); ++i) {
//     string s;
//     i->second->AppendToString(&s);
//     fprintf(stderr, "%lu: %s [%d]\n", i->first, s.c_str(), *(int*)(i->first));
//   }
//   for (size_t i = 0; i < stack_.size(); i++) {
//     string s;
//     if (stack_[i].expr) {
//       stack_[i].expr->AppendToString(&s);
//     } else if ((i == stack_.size() - 1) && pred_) {
//       pred_->AppendToString(&s);
//     }
//     fprintf(stderr, "s%zu: %lld [ %s ]\n", i, stack_[i].concrete, s.c_str());
//   }
// }


void SymbolicInterpreter::ClearStack(id_t id) {
  IFDEBUG(fprintf(stderr, "clear\n"));
  for (vector<StackElem>::const_iterator it = stack_.begin(); it != stack_.end(); ++it) {
    delete it->expr;
  }
  stack_.clear();
  ClearPredicateRegister();
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

  ClearPredicateRegister();
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
	// e will have op_type as DEREF and node type as UNARY_NODE
    // e = new SymbolicDeref(new SymbolicObject(obj), ty, se.expr);
	  e = new SymbolicExpr(se.expr, NULL, DEREF, NONLINEAR, se.expr->get_binary_op(), se.expr->get_unary_op(), NULL, value);
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

  ClearPredicateRegister();
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
  ClearPredicateRegister();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::Write(id_t id, addr_t addr) {
  IFDEBUG(fprintf(stderr, "store %lu\n", addr));
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

  ClearPredicateRegister();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyUnaryOp(id_t id, unary_op_t op,
                                       type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "apply1 %d %lld\n", op, value));
  assert(stack_.size() >= 1);
  StackElem& se = stack_.back();

  if (se.expr) {
    switch (op) {
    case ops::NEGATE:
      se.expr->Negate();
      ClearPredicateRegister();
      break;
    case ops::LOGICAL_NOT:
      if (pred_) {
    	  pred_->Negate();
      }
    break;

    case ops::BITWISE_NOT:
    	*se.expr = (*se.expr).applyUnary(ops::BITWISE_NOT);
    	break;

      // Otherwise, fall through to the concrete case.
    default:
      // Concrete operator.
      delete se.expr;
      se.expr = NULL;
      ClearPredicateRegister();
    }
  }

  se.concrete = value;
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyBinaryOp(id_t id, binary_op_t op,
                                        type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "apply2 %d %lld\n", op, value));
  assert(stack_.size() >= 2);
  StackElem& a = *(stack_.rbegin()+1);
  StackElem& b = stack_.back();

  if (a.expr || b.expr) {
    switch (op) {
    case ops::ADD:
      if (a.expr == NULL) {
    	  swap(a, b);
    	  *a.expr += b.concrete;
      } else if (b.expr == NULL) {
	*a.expr += b.concrete;
      } else {
	*a.expr += *b.expr;
	delete b.expr;
      }
      break;

    case ops::SUBTRACT:
      if (a.expr == NULL) {
	b.expr->Negate();
	swap(a, b);
	*a.expr += b.concrete;
      } else if (b.expr == NULL) {
	*a.expr -= b.concrete;
      } else {
	*a.expr -= *b.expr;
	delete b.expr;
      }
      break;

    case ops::MULTIPLY:
      if (a.expr == NULL) {
	swap(a, b);
	*a.expr *= b.concrete;
      } else if (b.expr == NULL) {
	*a.expr *= b.concrete;
      } else {
	swap(a, b);
	*a.expr *= b.concrete;
	delete b.expr;
      }
      break;

    case ops::SHIFT_L:
    	if(a.expr == NULL) {
    		value_t temp_value = a.concrete<<b.concrete;
    		*a.expr = SymbolicExpr(temp_value);
    		delete b.expr;
    	}
    	else {
    		SymbolicExpr temp(b.concrete);
    		*a.expr = (*a.expr).applyBinary(temp, ops::SHIFT_L);
    		delete b.expr;
    	}
    	break;

	case ops::SHIFT_R:
		if(a.expr == NULL) {
			value_t temp_value = a.concrete>>b.concrete;
		  	*a.expr = SymbolicExpr(temp_value);
	  		delete b.expr;
	  	}
	 	else {
	   		SymbolicExpr temp(b.concrete);
	   		*a.expr = (*a.expr).applyBinary(temp, ops::SHIFT_R);
	   		delete b.expr;
	   	}
		break;

	case ops::BITWISE_AND:
		if(a.expr == NULL) {
			swap(a,b);
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_AND);
		}
		else if(b.expr == NULL) {
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_AND);
		}
		else {
			*a.expr = (*a.expr).applyBinary(*b.expr, ops::BITWISE_AND);
		}
		break;

	case ops::BITWISE_OR:
		if(a.expr == NULL) {
			swap(a,b);
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_OR);
		}
		else if(b.expr == NULL) {
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_OR);
		}
		else {
			*a.expr = (*a.expr).applyBinary(*b.expr, ops::BITWISE_OR);
		}
		break;

	case ops::BITWISE_XOR:
		if(a.expr == NULL) {
			swap(a,b);
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_XOR);
		}
		else if(b.expr == NULL) {
			SymbolicExpr temp(b.concrete);
			*a.expr = (*a.expr).applyBinary(temp, ops::BITWISE_XOR);
		}
		else {
			*a.expr = (*a.expr).applyBinary(*b.expr, ops::BITWISE_XOR);
		}
		break;

    default:
      // Concrete operator.
      delete a.expr;
      delete b.expr;
      a.expr = NULL;
    }
  }

  a.concrete = value;
  stack_.pop_back();
  ClearPredicateRegister();
  IFDEBUG(DumpMemory());
}


void SymbolicInterpreter::ApplyCompareOp(id_t id, compare_op_t op,
                                         type_t ty, value_t value) {
  IFDEBUG(fprintf(stderr, "compare2 %d %lld\n", op, value));
  assert(stack_.size() >= 2);
  StackElem& a = *(stack_.rbegin()+1);
  StackElem& b = stack_.back();

  if (a.expr || b.expr) {
    // Symbolically compute "a -= b".
    if (a.expr == NULL) {
      b.expr->Negate();
      swap(a, b);
      *a.expr += b.concrete;
    } else if (b.expr == NULL) {
      *a.expr -= b.concrete;
    } else {
      *a.expr -= *b.expr;
      delete b.expr;
    }
    // Construct a symbolic predicate (if "a - b" is symbolic), and
    // store it in the predicate register.
    if (!a.expr->IsConcrete()) {
      pred_ = new SymbolicPred(op, a.expr);
    } else {
      ClearPredicateRegister();
      delete a.expr;
    }
    // We leave a concrete value on the stack.
    a.expr = NULL;
  }

  a.concrete = value;
  stack_.pop_back();
  IFDEBUG(DumpMemory());
}

  //void SymbolicInterpreter::ApplyDeref() {
    //STUB
  //}

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
  stack_.pop_back();

  if (pred_ && !pred_value) {
    pred_->Negate();
  }

  ex_.mutable_path()->Push(bid, pred_);
  pred_ = NULL;
  IFDEBUG(DumpMemory());
}


value_t SymbolicInterpreter::NewInput(type_t ty, addr_t addr) {
  assert(ty != types::STRUCT);

  // Construct new symbolic expr and concrete value of type 'ty'.
  SymbolicExpr* e = NULL;
  value_t ret = 0;

  // Somehow combine bytes num_inputs_, ..., num_inputs+kSizeOfType[ty]-1,
  // into a symbolic expression.
  for (size_t i = 0; i < kSizeOfType[ty]; i++) {
    ex_.mutable_vars()->insert(make_pair(num_inputs_ + i, ty));

    value_t val = 0;
    if (num_inputs_ + i < ex_.inputs().size()) {
      val = ex_.inputs()[num_inputs_ + i];
    } else {
      // New inputs are initially zero.  (Could randomize instead.)
      ex_.mutable_inputs()->push_back(0);
    }

    ret = ret << 8 + val;
  }

  mem_.write(addr, ty, e);
  return ret;
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


void SymbolicInterpreter::ClearPredicateRegister() {
  delete pred_;
  pred_ = NULL;
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
