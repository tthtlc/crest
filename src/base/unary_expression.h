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
 * Author: Sudeep Juvekar (sjuvekar@eecs.berkeley.edu)
 */
#ifndef UNARY_EXPRESSION_H__
#define UNARY_EXPRESSION_H__

#include "base/basic_types.h"
#include "base/symbolic_expression.h"

namespace crest {

class UnaryExpr : public SymbolicExpr {
 public:
  UnaryExpr(ops::unary_op_t op, SymbolicExpr *c, size_t s, value_t v);
  ~UnaryExpr();

  UnaryExpr* Clone() const;

  void AppendVars(set<var_t>* vars) const;
  bool DependsOn(const map<var_t,type_t>& vars) const;
  void AppendToString(string *s) const;
  void Serialize(string* s) const;
  bool IsConcrete() const { return false; }

  yices_expr bit_blast(yices_context ctx) const;
  UnaryExpr* castUnaryExpr() { return this; }
  bool Equals(const SymbolicExpr &e) const;

  // Accessors
  ops::unary_op_t unary_op() const { return unary_op_; }
  const SymbolicExpr* child() const { return child_; }

 private:
  const SymbolicExpr *child_;
  const ops::unary_op_t unary_op_;
};

}  // namespace crest

#endif  // UNARY_EXPRESSION_H__
