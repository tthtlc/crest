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
#include "base/unary_expression.h"

namespace crest {

UnaryExpr::UnaryExpr(ops::unary_op_t op, SymbolicExpr *c, size_t s, value_t v)
  : SymbolicExpr(v,s), unary_op_(op), child_(c) { }

UnaryExpr::~UnaryExpr() {
  delete child_;
}

size_t UnaryExpr::Size() {
  return child_->Size()+1;
}

void UnaryExpr::AppendVars(set<var_t>* vars) {
  child_->AppendVars(vars);
}

bool UnaryExpr::DependsOn(const map<var_t,type_t>& vars) {
  return child_->DependsOn(vars);
}

void UnaryExpr::AppendToString(string *s) {
  char buff[32];
  sprintf(buff, " (%u", unary_op_);
  s->append(buff);
  child_->AppendToString(s);
  s->append(")");
}

bool UnaryExpr::IsConcrete() {
  return false;
}

void UnaryExpr::bit_blast(yices_expr &e,  yices_context &ctx, map<var_t,yices_var_decl> &x_decl) {
  switch (unary_op_) {
  case ops::NEGATE:
    if(child_)
      child_->bit_blast(e, ctx, x_decl);
    e = yices_mk_bv_minus(ctx,e);
    break;

  case ops::LOGICAL_NOT:
    if (child_)
      child_->bit_blast(e, ctx, x_decl);
    e = yices_mk_not(ctx, e);
    break;

  case ops::BITWISE_NOT:
    if (child_)
      child_->bit_blast(e, ctx, x_decl);
    e = yices_mk_bv_not(ctx, e);
    break;

  default:
    fprintf(stderr, "Unknown unary operator: %d\n", unary_op_);
    exit(1);
    break;
  }
}

}  // namespace crest
