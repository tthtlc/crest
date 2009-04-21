// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#ifndef BASE_SYMBOLIC_EXPRESSION_H__
#define BASE_SYMBOLIC_EXPRESSION_H__

#include <istream>
#include <map>
#include <vector>
#include <ostream>
#include <set>
#include <string>

#include "base/basic_types.h"
#include "base/linear_expression.h"

using std::istream;
using std::map;
using std::ostream;
using std::set;
using std::string;
using std::vector;

namespace crest {

namespace node {
	enum op_type {UNARY, BINARY, DEREF};
	enum node_type {LINEAR, NONLINEAR};
}
using namespace node;

class SymbolicExpr {
 public:
  // Constructs a symbolic expression for the constant 0.
  SymbolicExpr();

  // Constructs a symbolic expression for the given constant 'c'.
  explicit SymbolicExpr(value_t c);

  // Constructs a symbolic expression for the singleton 'c' * 'v'.
  SymbolicExpr(value_t c, var_t v);

  // Copy constructor.
  SymbolicExpr(const SymbolicExpr& e);

  //Construct a symbolic expression from left, right, and types
  SymbolicExpr(SymbolicExpr *l, SymbolicExpr *r, op_type op,
		  node_type no, ops::binary_op_t binop, ops::unary_op_t unop, LinearExpr *exp,
		  value_t v);
  // Desctructor.
  ~SymbolicExpr();

  void Negate();
  bool IsConcrete() const { return ( node_type_ == LINEAR && expr_->IsConcrete() ); }
  size_t Size();
  void AppendVars(set<var_t>* vars) const;
  bool DependsOn(const map<var_t,type_t>& vars) const;

  void AppendToString(string* s) const;

  void Serialize(string* s) const;
  bool Parse(istream& s);

  // Arithmetic operators.
  const SymbolicExpr& operator+=(SymbolicExpr& e);
  const SymbolicExpr& operator-=(SymbolicExpr& e);
  const SymbolicExpr& operator+=(value_t c);
  const SymbolicExpr& operator-=(value_t c);
  const SymbolicExpr& operator*=(value_t c);
  bool operator==(const SymbolicExpr& e) const;
  SymbolicExpr& applyUnary(ops::unary_op_t op); //The operator is other than Negate
  SymbolicExpr& applyBinary(SymbolicExpr &e, ops::binary_op_t op); //The operator is other than +,-and constant multiply
  SymbolicExpr& applyDeref(); // Pointer deref

  // Accessors.
  value_t const_term();
  const map<var_t,value_t>& terms();
  typedef map<var_t,value_t>::const_iterator TermIt;
  LinearExpr *linear_expr() {return expr_; }
  node_type get_node_type() {return node_type_;}
  op_type get_op_type() { return op_type_; }
  ops::binary_op_t get_binary_op() { return binary_op_; };
  ops::unary_op_t get_unary_op() { return unary_op_; }
  SymbolicExpr *getLeft() { return left_;}
  SymbolicExpr *getRight() { return right_;}
  value_t getValue() { return value_; }
  types::type_t getType() { return type_; }

 private:
	 LinearExpr *expr_;
	 SymbolicExpr *left_, *right_;
	 op_type op_type_;
	 node_type node_type_;
	 ops::binary_op_t binary_op_;
	 ops::unary_op_t unary_op_;
	 types::type_t type_;
	 value_t value_;
	 vector<SymbolicExpr> symbolic_writes_;

	 static value_t Apply(ops::binary_op_t bin_op, value_t v1, value_t v2);
	 static value_t Apply(ops::unary_op_t un_op, value_t v);
};

}  // namespace crest

#endif  // BASE_SYMBOLIC_EXPRESSION_H__
