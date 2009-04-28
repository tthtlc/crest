// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
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
#include "base/binary_expression.h"

namespace crest {

BinaryExpr::BinaryExpr(ops::binary_op_t op, SymbolicExpr *l, SymbolicExpr *r,
                       size_t s, value_t v)
  : SymbolicExpr(s,v), binary_op_(op), left_(l), right_(r) { }

BinaryExpr::~BinaryExpr() {
  delete left_;
  delete right_;
}

BinaryExpr* BinaryExpr::Clone() const {
  return new BinaryExpr(binary_op_, left_->Clone(), right_->Clone(),
                        size(), value());
}

void BinaryExpr::AppendVars(set<var_t>* vars) const {
  left_->AppendVars(vars);
  right_->AppendVars(vars);
}

bool BinaryExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return left_->DependsOn(vars) || right_->DependsOn(vars);
}

void BinaryExpr::AppendToString(string *s) const {
  s->append("(");
  s->append(kBinaryOpStr[binary_op_]);
  s->append(" ");
  left_->AppendToString(s);
  s->append(" ");
  right_->AppendToString(s);
  s->append(")");
}

yices_expr BinaryExpr::BitBlast(yices_context ctx) const {
  yices_expr e1 = left_->BitBlast(ctx);
  yices_expr e2 = right_->BitBlast(ctx);
  unsigned end = 0, start = 0;

  switch (binary_op_) {
  case ops::ADD:
    return yices_mk_bv_add(ctx, e1, e2);
  case ops::SUBTRACT:
    return yices_mk_bv_sub(ctx, e1, e2);
  case ops::MULTIPLY:
    return yices_mk_bv_mul(ctx, e1, e2);
    break;
  case ops::SHIFT_L:
    // Assumption: right_ is concrete.
    return yices_mk_bv_shift_left0(ctx, e1, right_->value());
    break;
  case ops::SHIFT_R:
    // Assumption: right_ is concrete.
    return yices_mk_bv_shift_right0(ctx, e1, right_->value());
    break;
  case ops::S_SHIFT_R:
    // Assumption: right_ is concrete.
    return yices_mk_bv_shift_right1(ctx, e1, right_->value());
    break;
  case ops::BITWISE_AND:
    return yices_mk_bv_and(ctx, e1, e2);
  case ops::BITWISE_OR:
    return yices_mk_bv_or(ctx, e1, e2);
  case ops::BITWISE_XOR:
    return yices_mk_bv_xor(ctx, e1, e2);
  case ops::CONCAT:
    return yices_mk_bv_concat(ctx, e1, e2);
  case ops::EXTRACT:
    // Assumption: right_ is concrete.
    end = 8*(size() - right_->value()) - 1;
    start = end - 7;
    return yices_mk_bv_extract(ctx, end, start, e1);
  default:
    fprintf(stderr, "Unknown/unhandled binary operator: %d\n", binary_op_);
    exit(1);
  }
}

void BinaryExpr::Serialize(string* s) const {
  // s->append((char*)binary_op_, sizeof(binary_op_t));
  s->push_back('(');
  left_->Serialize(s);
  right_->Serialize(s);
  s->push_back(')');
}

bool BinaryExpr::Equals(const SymbolicExpr &e) const {
  const BinaryExpr* b = e.CastBinaryExpr();
  return ((b != NULL)
          && (binary_op_ == b->binary_op_)
          && left_->Equals(*b->left_)
          && right_->Equals(*b->right_));
}
}  // namespace crest
