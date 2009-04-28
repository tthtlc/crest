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

#ifndef BINARY_EXPRESSION_H__
#define BINARY_EXPRESSION_H__

#include "base/basic_types.h"
#include "base/symbolic_expression.h"

namespace crest {

class BinaryExpr : public SymbolicExpr {
 public:
  BinaryExpr(ops::binary_op_t op, SymbolicExpr *l, SymbolicExpr *r,
             size_t size, value_t val);
  ~BinaryExpr();

  BinaryExpr* Clone() const;

  void AppendVars(set<var_t>* vars) const;
  bool DependsOn(const map<var_t,type_t>& vars) const;
  void AppendToString(string *s) const;
  bool IsConcrete() const { return false; }
  yices_expr bit_blast(yices_context ctx) const;

  BinaryExpr* castBinaryExpr() { return this; }
  bool Equals(const SymbolicExpr &e) const;

  // Accessors
  const ops::binary_op_t get_binary_op() const { return binary_op_; }
  const SymbolicExpr* get_left() const { return left_; }
  const SymbolicExpr* get_right() const { return right_; }

 private:
  const ops::binary_op_t binary_op_;
  const SymbolicExpr *left_, *right_;
};

}  // namespace crest

#endif  // BINARY_EXPRESSION_H__
