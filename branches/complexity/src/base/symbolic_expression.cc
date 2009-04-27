// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

/***
 * Author: Sudeep juvekar (sjuvekar@eecs.berkeley.edu)
 * 4/17/09
 */
#include <assert.h>
#include "base/symbolic_expression.h"
#include "base/unary_expression.h"
#include "base/binary_expression.h"
#include "base/compare_expression.h"
#include "base/deref_expression.h"
#include "base/symbolic_object.h"

namespace crest {

typedef map<var_t,value_t>::iterator It;
typedef map<var_t,value_t>::const_iterator ConstIt;

SymbolicExpr& SymbolicExpr::applyUnary(ops::unary_op_t op) {
  UnaryExpr *un_exp = new UnaryExpr(op, this, size_in_bytes_, Apply(op, value_));
  return *un_exp;
}

SymbolicExpr& SymbolicExpr::applyBinary(SymbolicExpr &e, ops::binary_op_t op) {
  BinaryExpr *bin_exp = new BinaryExpr(op, this, &e, RETURN_SIZE__(size_in_bytes_, e.size_in_bytes_), Apply(op, value_, e.value_));
  return *bin_exp;
}

SymbolicExpr& SymbolicExpr::applyCompare(SymbolicExpr &e, ops::compare_op_t op) {
  value_t res = (value_t)Apply(op, value_, e.value_);
  CompareExpr *comp_exp = new CompareExpr(op, this, &e, 1, res);
  return *comp_exp;
}

SymbolicExpr& SymbolicExpr::applyDeref() {
  //TODO:
  SymbolicExpr *temp = new SymbolicExpr();
  return *temp;
}

value_t SymbolicExpr::Apply(ops::binary_op_t bin_op, value_t v1, value_t v2) {
  switch(bin_op) {
  case ops::ADD: return v1+v2;
  case ops::SUBTRACT: return v1-v2;
  case ops::MULTIPLY: return v1*v2;
  case ops::SHIFT_L: return v1<<v2;
  case ops::SHIFT_R: return v1>>v2;
  case ops::BITWISE_AND: return v1&v2;
  case ops::BITWISE_OR: return v1|v2;
  case ops::BITWISE_XOR: return v1^v2;
  case ops::CONCAT: return v1+v2;
  case ops::EXTRACT: return v2;
  default:
    fprintf(stderr,"Unknown binary operator %d\n", bin_op);
    exit(1);
  }
}

bool SymbolicExpr::Apply(ops::compare_op_t comp_op, value_t v1, value_t v2) {
  switch(comp_op) {
  case ops::EQ: return v1==v2;
  case ops::NEQ: return v1!=v2;
  case ops::GT: return v1>v2;
  case ops::GE: return v1>=v2;
  case ops::LT: return v1<v2;
  case ops::LE: return v1<=v2;
  default:
    fprintf(stderr,"Unknown comparison operator %d\n", comp_op);
    exit(1);
  }
}

value_t SymbolicExpr::Apply(ops::unary_op_t un_op, value_t v) {
  switch(un_op) {
  case ops::NEGATE: return 0 - v;
  case ops::BITWISE_NOT: return ~v;
  case ops::LOGICAL_NOT: return !v;
  default:
    fprintf(stderr, "Unknown unary operator %d\n", un_op);
    exit(1);
  }
}



SymbolicExpr* SymbolicExpr::NewConcreteExpr(size_t s, value_t val) {
  return new SymbolicExpr(val, s);
}

SymbolicExpr* SymbolicExpr::NewConstDeref(const SymbolicObject& obj, addr_t addr, size_t s, value_t val) {
  DerefExpr *deref_expr = new DerefExpr(new SymbolicExpr(addr, SIZEOF_ULONG__), new SymbolicObject(obj), s, val);
  return deref_expr;
}

SymbolicExpr* SymbolicExpr::Concatenate(SymbolicExpr *e1, SymbolicExpr *e2) {
  return &e1->applyBinary(*e2, ops::CONCAT);
}

SymbolicExpr* SymbolicExpr::ExtractByte(const SymbolicExpr& e, size_t i) {
  return new BinaryExpr(ops::EXTRACT, new SymbolicExpr(e), new SymbolicExpr(i, SIZEOF_ULONG__), SIZEOF_ULONG__,0);
}

}  // namespace crest
