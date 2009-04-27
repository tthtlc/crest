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

BinaryExpr::BinaryExpr(ops::binary_op_t op, SymbolicExpr *l, SymbolicExpr *r, size_t s, value_t v)
  : SymbolicExpr(v,s), binary_op_(op), left_(l), right_(r) { }

BinaryExpr::~BinaryExpr() {
  delete left_;
  delete right_;
}

size_t BinaryExpr::Size() {
  return left_->Size() + right_->Size() + 1;
}

void BinaryExpr::AppendVars(set<var_t>* vars) {
  left_->AppendVars(vars);
  right_->AppendVars(vars);
}

bool BinaryExpr::DependsOn(const map<var_t,type_t>& vars) {
  return left_->DependsOn(vars) || right_->DependsOn(vars);
}

void BinaryExpr::AppendToString(string *s) {
  char buff[32];
  sprintf(buff, " (%u", binary_op_);
  s->append(buff);
  left_->AppendToString(s);
  right_->AppendToString(s);
  s->append(")");
}

bool BinaryExpr::IsConcrete() {
  return false;
}

bool BinaryExpr::operator==(BinaryExpr &e) {
  return *left_ == *e.left_ && *right_ == *e.right_;
}


void BinaryExpr::bit_blast(yices_expr &e, yices_context &ctx, map<var_t,yices_var_decl> &x_decl) {
  unsigned temp_n = right_->get_value();
  yices_expr *e1=NULL, *e2=NULL;
  if (left_)
    left_->bit_blast(*e1, ctx, x_decl);
  if (right_)
    right_->bit_blast(*e2, ctx, x_decl);

  switch (binary_op_) {
  case ops::ADD:
    e = yices_mk_bv_add(ctx, *e1, *e2);
    break;
  case ops::SUBTRACT:
    e = yices_mk_bv_sub(ctx, *e1, *e2);
    break;
  case ops::MULTIPLY:
    e = yices_mk_bv_mul(ctx, *e1, *e2);
    break;
  case ops::SHIFT_L:
    e = yices_mk_bv_shift_left0(ctx, *e1, temp_n);
    break;
  case ops::SHIFT_R:
    e = yices_mk_bv_shift_right0(ctx, *e1, temp_n);
    break;
  case ops::BITWISE_AND:
    e = yices_mk_bv_and(ctx, *e1, *e2);
  case ops::BITWISE_OR:
    e = yices_mk_bv_or(ctx, *e1, *e2);
  case ops::BITWISE_XOR:
    e = yices_mk_bv_xor(ctx, *e1, *e2);
  case ops::CONCAT:
    e = yices_mk_bv_concat(ctx, e1, e2);
  default:
    fprintf(stderr, "Unknown binary operator: %d\n", binary_op_);
    exit(1);
    break;
  }

  delete e1;
  delete e2;
}

}  // namespace crest
