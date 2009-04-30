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
  size_t child_size = 0;
  size_t curr_size = 0;

  switch (unary_op_) {
  case ops::NEGATE:
    return yices_mk_bv_minus(ctx, e);

  case ops::LOGICAL_NOT:
    return yices_mk_not(ctx, e);

  case ops::BITWISE_NOT:
    return yices_mk_bv_not(ctx, e);

  case ops::CAST:
	child_size = 8*child_->size();
	curr_size = 8*size();

	if(curr_size < child_size) { // Downcast: Extract the lowest order bits
		return yices_mk_bv_extract(ctx, curr_size - 1, 0, e);
	}
	else if(curr_size > child_size) { //Upcast: sign-extend
		return yices_mk_bv_sign_extend(ctx, e, curr_size - child_size);
	}
	else {
		return e;
	}

  default:
    fprintf(stderr, "Unknown unary operator: %d\n", unary_op_);
    exit(1);
  }
}

void UnaryExpr::Serialize(string* s) const {
	SymbolicExpr::Serialize(s, kUnaryNodeTag);
	s->push_back(unary_op_);
	child_->Serialize(s);
}

bool UnaryExpr::Equals(const SymbolicExpr &e) const {
  const UnaryExpr* u = e.CastUnaryExpr();
  return ((u != NULL)
          && (unary_op_ == u->unary_op_)
          && child_->Equals(*u->child_));
}
}  // namespace crest
