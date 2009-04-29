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
  : SymbolicExpr(s, v), child_(c), unary_op_(op) { }

UnaryExpr::~UnaryExpr() {
  delete child_;
}

UnaryExpr* UnaryExpr::Clone() const {
  return new UnaryExpr(unary_op_, child_->Clone(), size(), value());
}

void UnaryExpr::AppendVars(set<var_t>* vars) const {
  child_->AppendVars(vars);
}

bool UnaryExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return child_->DependsOn(vars);
}

void UnaryExpr::AppendToString(string *s) const {
  s->append("(");
  s->append(kUnaryOpStr[unary_op_]);
  s->append(" ");
  child_->AppendToString(s);
  s->append(")");
}

yices_expr UnaryExpr::BitBlast(yices_context ctx) const {
  yices_expr e = child_->BitBlast(ctx);

  switch (unary_op_) {
  case ops::NEGATE:
    return yices_mk_bv_minus(ctx, e);

  case ops::LOGICAL_NOT:
    return yices_mk_not(ctx, e);

  case ops::BITWISE_NOT:
    return yices_mk_bv_not(ctx, e);

  case ops::CAST:
	fprintf(stderr, "Cast not handled yet!...exiting\n");
	exit(1);

  default:
    fprintf(stderr, "Unknown unary operator: %d\n", unary_op_);
    exit(1);
  }
}

void UnaryExpr::Serialize(string* s) const {
	SymbolicExpr::Serialize(s, UNARY_NODE_TYPE);
	//s->push_back(UNARY_NODE_TYPE);
	s->append(__UNARY_OP_STR[unary_op_], __SIZEOF_UNARY_OP);
	child_->Serialize(s);
}

bool UnaryExpr::Equals(const SymbolicExpr &e) const {
  const UnaryExpr* u = e.CastUnaryExpr();
  return ((u != NULL)
          && (unary_op_ == u->unary_op_)
          && child_->Equals(*u->child_));
}
}  // namespace crest
