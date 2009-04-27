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

#include <istream>
#include <map>
#include <vector>
#include <ostream>
#include <set>
#include <string>
#include <yices_c.h>

#include "base/basic_types.h"
#include "base/symbolic_object.h"
#include "base/symbolic_expression.h"

using std::istream;
using std::map;
using std::ostream;
using std::set;
using std::string;
using std::vector;

namespace crest {

class UnaryExpr : public SymbolicExpr {
 public:
  UnaryExpr(ops::unary_op_t op, SymbolicExpr *c, size_t s, value_t v);
  ~UnaryExpr();
  size_t Size();
  void AppendVars(set<var_t>* vars);
  bool DependsOn(const map<var_t,type_t>& vars);
  void AppendToString(string *s);
  bool IsConcrete();
  void bit_blast(yices_expr &e, yices_context &ctx, map<var_t, yices_var_decl> &x_decl);

  // Accessors
  ops::unary_op_t get_unary_op() { return unary_op_; }
  SymbolicExpr* get_child() { return child_; }

 private:
  ops::unary_op_t unary_op_;
  SymbolicExpr *child_;
};

}  // namespace crest

#endif  // UNARY_EXPRESSION_H__
