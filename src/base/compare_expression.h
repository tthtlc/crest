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
 * Author: Sudeep Juvekar (sjuvekar@eecs.berkeley.edu)
 */

#ifndef COMPARE_EXPRESSION_H_
#define COMPARE_EXPRESSION_H_

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

/***
  * Compare Expression
  */
 class CompareExpr : public SymbolicExpr {
 private:
	 ops::compare_op_t compare_op_;
	 SymbolicExpr *left_, *right_;

 public:
	 CompareExpr(ops::compare_op_t op, SymbolicExpr *l, SymbolicExpr *r, size_t s, value_t v);
	 ~CompareExpr();
	 size_t Size();
	 void AppendVars(set<var_t>* vars);
	 bool DependsOn(const map<var_t,type_t>& vars);
	 void AppendToString(string *s);
	 bool IsConcrete();
	 bool operator==(CompareExpr &e);
	 void bit_blast(yices_expr &e, yices_context &ctx, map<var_t, yices_var_decl> &x_decl);

	 //Accessor
	 ops::compare_op_t get_compare_op() { return compare_op_; }
	 SymbolicExpr* get_left()  { return left_; }
	 SymbolicExpr* get_right() { return right_; }

 };


}
#endif /* COMPARE_EXPRESSION_H_ */
