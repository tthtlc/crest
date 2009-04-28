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

#include <yices_c.h>

#include "base/symbolic_expression.h"
#include "base/unary_expression.h"
#include "base/binary_expression.h"
#include "base/compare_expression.h"
#include "base/deref_expression.h"
#include "base/symbolic_object.h"

namespace crest {

typedef map<var_t,value_t>::iterator It;
typedef map<var_t,value_t>::const_iterator ConstIt;

SymbolicExpr::~SymbolicExpr() { }

SymbolicExpr* SymbolicExpr::Clone() const {
  return new SymbolicExpr(size_, value_);
}

bool SymbolicExpr::Equals(const SymbolicExpr &e) const {
  return (e.IsConcrete()
          && (value() == e.value())
          && (size() == e.size()));
}

yices_expr SymbolicExpr::BitBlast(yices_context ctx) const {
  // TODO: Implement this method for size() > sizeof(unsigned long).
  assert(size() <= sizeof(unsigned long));
  return yices_mk_bv_constant(ctx, 8*size(), (unsigned long)value());
}

SymbolicExpr* SymbolicExpr::NewConcreteExpr(type_t ty, value_t val) {
  return new SymbolicExpr(kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewUnaryExpr(type_t ty, value_t val,
                                         ops::unary_op_t op, SymbolicExpr* e) {
  return new UnaryExpr(op, e, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewBinaryExpr(type_t ty, value_t val,
                                          ops::binary_op_t op,
                                          SymbolicExpr* e1, SymbolicExpr* e2) {
  return new BinaryExpr(op, e1, e2, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewCompareExpr(type_t ty, value_t val,
                                           ops::compare_op_t op,
                                           SymbolicExpr* e1, SymbolicExpr* e2) {
  return new CompareExpr(op, e1, e2, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewConstDeref(type_t ty, value_t val,
                                          const SymbolicObject& obj,
                                          addr_t addr) {
  return new DerefExpr(NewConcreteExpr(types::U_LONG, addr),
                       new SymbolicObject(obj), kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewDeref(type_t ty, value_t val,
                                     const SymbolicObject& obj,
                                     SymbolicExpr* addr) {
  return new DerefExpr(addr, new SymbolicObject(obj), kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::Concatenate(SymbolicExpr *e1, SymbolicExpr *e2) {
  return new BinaryExpr(ops::CONCAT, e1, e2,
                        e1->size() + e2->size(),
                        (e1->value() << (8 * e2->size())) + e2->value());
}

SymbolicExpr* SymbolicExpr::ExtractByte(SymbolicExpr* e, size_t i) {
  // Extract i-th most significant byte.
  value_t val = (e->value() >> (e->size() - i - 1)) & 0xFF;
  SymbolicExpr* i_e = NewConcreteExpr(types::U_LONG, i);
  return new BinaryExpr(ops::EXTRACT, e, i_e,  1, val);
}

}  // namespace crest
