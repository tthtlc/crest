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
#include "base/compare_expression.h"

namespace crest {

CompareExpr::CompareExpr(ops::compare_op_t op, SymbolicExpr *l, SymbolicExpr *r, size_t s, value_t v)
  : SymbolicExpr(v,s), compare_op_(op), left_(l), right_(r) { }

CompareExpr::~CompareExpr() {
  delete left_;
  delete right_;
}

size_t CompareExpr::Size() {
  return left_->Size() + right_->Size() + 1;
}

void CompareExpr::AppendVars(set<var_t>* vars) {
  left_->AppendVars(vars);
  right_->AppendVars(vars);
}

bool CompareExpr::DependsOn(const map<var_t,type_t>& vars) {
  return left_->DependsOn(vars) || right_->DependsOn(vars);
}

void CompareExpr::AppendToString(string *s) {
  char buff[32];
  sprintf(buff, " (%u", compare_op_);
  s->append(buff);
  left_->AppendToString(s);
  right_->AppendToString(s);
  s->append(")");
}

bool CompareExpr::IsConcrete() {
  return false;
}

bool CompareExpr::operator==(CompareExpr &e) {
  return *left_ == *e.left_ && *right_ == *e.right_;
}


void CompareExpr::bit_blast(yices_expr &e, yices_context &ctx, map<var_t,yices_var_decl> &x_decl) {
  yices_expr *e1 = NULL, *e2 = NULL;
  if (left_)
    left_->bit_blast(*e1, ctx, x_decl);
  if (right_)
    right_->bit_blast(*e2, ctx, x_decl);

  switch (compare_op_) {
  case ops::GE:
    e = yices_mk_bv_ge(ctx, *e1, *e2);
    break;
  case ops::GT:
    e = yices_mk_bv_gt(ctx, *e1, *e2);
    break;
  case ops::LE:
    e = yices_mk_bv_le(ctx, *e1, *e2);
    break;
  case ops::LT:
    e = yices_mk_bv_lt(ctx, *e1, *e2);
    break;
  default:
    fprintf(stderr, "Unknown comparison operator: %d\n", compare_op_);
    exit(1);
  }

  delete e1;
  delete e2;
}

}  // namespace crest
