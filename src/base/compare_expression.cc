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
#include <yices_c.h>
#include "base/compare_expression.h"

namespace crest {

CompareExpr::CompareExpr(ops::compare_op_t op, SymbolicExpr *l, SymbolicExpr *r, size_t s, value_t v)
  : SymbolicExpr(s, v), compare_op_(op), left_(l), right_(r) { }

CompareExpr::~CompareExpr() {
  delete left_;
  delete right_;
}

CompareExpr* CompareExpr::Clone() const {
  return new CompareExpr(compare_op_, left_->Clone(), right_->Clone(),
                         size(), value());
}

void CompareExpr::AppendVars(set<var_t>* vars) const {
  left_->AppendVars(vars);
  right_->AppendVars(vars);
}

bool CompareExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return left_->DependsOn(vars) || right_->DependsOn(vars);
}

void CompareExpr::AppendToString(string *s) const {
  char buff[32];
  sprintf(buff, " (%u", compare_op_);
  s->append(buff);
  left_->AppendToString(s);
  right_->AppendToString(s);
  s->append(")");
}

yices_expr CompareExpr::BitBlast(yices_context ctx) const {
  yices_expr e1 = left_->BitBlast(ctx);
  yices_expr e2 = right_->BitBlast(ctx);

  switch (compare_op_) {
  case ops::EQ:
    return yices_mk_eq(ctx, e1, e2);
  case ops::NEQ:
    return yices_mk_diseq(ctx, e1, e2);
  case ops::GT:
    return yices_mk_bv_gt(ctx, e1, e2);
  case ops::LE:
    return yices_mk_bv_le(ctx, e1, e2);
  case ops::LT:
    return yices_mk_bv_lt(ctx, e1, e2);
  case ops::GE:
    return yices_mk_bv_ge(ctx, e1, e2);
  case ops::S_GT:
    return yices_mk_bv_sgt(ctx, e1, e2);
  case ops::S_LE:
    return yices_mk_bv_sle(ctx, e1, e2);
  case ops::S_LT:
    return yices_mk_bv_slt(ctx, e1, e2);
  case ops::S_GE:
    return yices_mk_bv_sge(ctx, e1, e2);
  default:
    fprintf(stderr, "Unknown comparison operator: %d\n", compare_op_);
    exit(1);
  }
}

void CompareExpr::Serialize(string* s) const {
  s->append((char*)compare_op_, sizeof(compare_op_t));
  s->push_back('(');
  left_->Serialize(s);
  right_->Serialize(s);
  s->push_back(')');
}

bool CompareExpr::Equals(const SymbolicExpr &e) const {
  const CompareExpr* c = e.CastCompareExpr();
  return ((c != NULL)
          && (compare_op_ == c->compare_op_)
          && left_->Equals(*c->left_)
          && right_->Equals(*c->right_));
}
}  // namespace crest
