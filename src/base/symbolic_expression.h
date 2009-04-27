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
 * Authors: Jacob Burnim (jburnim@cs.berkeley.edu)
 * 			Sudeep Juvekar (Sjuvekar@eecs.berkeley.edu)
 */
#ifndef BASE_SYMBOLIC_EXPRESSION_H__
#define BASE_SYMBOLIC_EXPRESSION_H__

#include <istream>
#include <map>
#include <vector>
#include <ostream>
#include <set>
#include <string>
#include <yices_c.h>

#include "base/basic_types.h"

using std::istream;
using std::map;
using std::ostream;
using std::set;
using std::string;
using std::vector;

namespace crest {

class SymbolicObject;

class SymbolicExpr {
 public:
  // Constructs a symbolic expression for the constant 0.
  SymbolicExpr() : value_(LONG_LONG_MIN), size_in_bytes_(sizeof(int)) {;}

  // Constructs a symbolic expression for the given constant 'c'.
  SymbolicExpr(value_t c) : value_(c) {;}

  //Constructor taking a value and type
  SymbolicExpr(value_t v, size_t s) : value_(v), size_in_bytes_(s) {;}

   // Desctructor.
  virtual ~SymbolicExpr() {;}

  virtual size_t Size() { return 0;}
  virtual void AppendVars(set<var_t>* vars) const {;}
  virtual bool DependsOn(const map<var_t,type_t>& vars) const { return false;}
  virtual void AppendToString(string* s) const {;}
  virtual bool IsConcrete() const { return false;}

  virtual void Serialize(string* s) const {;}
  virtual bool Parse(istream& s) { return true;}

  // Arithmetic operators.

  SymbolicExpr& applyUnary(ops::unary_op_t op);
  SymbolicExpr& applyBinary(SymbolicExpr &e, ops::binary_op_t op);
  SymbolicExpr& applyDeref(); // Pointer deref
  SymbolicExpr& applyCompare(SymbolicExpr &e, ops::compare_op_t op);
  virtual void bit_blast(yices_expr &e, yices_context &ctx, map<var_t, yices_var_decl> &x_decl) {;}
  virtual bool operator==(SymbolicExpr &e) {return false; }

  static inline value_t Apply(ops::binary_op_t bin_op, value_t v1, value_t v2);
  static inline bool Apply(ops::compare_op_t bin_op, value_t v1, value_t v2);
  static inline value_t Apply(ops::unary_op_t un_op, value_t v);

  // Factory methods for constructing symbolic expressions.
  static SymbolicExpr* NewConcreteExpr(size_t s, value_t val);
  static SymbolicExpr* NewConstDeref(const SymbolicObject &obj, addr_t addr, size_t ty, value_t val);
  static SymbolicExpr* Concatenate(SymbolicExpr* e1, SymbolicExpr* e2);
  static SymbolicExpr* ExtractByte(const SymbolicExpr& e, size_t i);

  // Accessors.
  value_t get_value() { return value_; }

 protected:
  value_t value_;
  size_t size_in_bytes_;
};

}  // namespace crest

#endif  // BASE_SYMBOLIC_EXPRESSION_H__
