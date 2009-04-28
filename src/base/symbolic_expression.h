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
 *          Sudeep Juvekar (Sjuvekar@eecs.berkeley.edu)
 */

// TODO:
// (1) Implement Parse
// Serialization is done using ( ) parantheses and prefix notation.

#ifndef BASE_SYMBOLIC_EXPRESSION_H__
#define BASE_SYMBOLIC_EXPRESSION_H__

#include <istream>
#include <map>
#include <set>
#include <string>

#include "base/basic_types.h"

using std::istream;
using std::map;
using std::set;
using std::string;

typedef void* yices_expr;
typedef void* yices_context;

namespace crest {

class SymbolicObject;
class UnaryExpr;
class BinaryExpr;
class DerefExpr;
class CompareExpr;
class BasicExpr;

class SymbolicExpr {
 public:
  virtual ~SymbolicExpr();

  virtual SymbolicExpr* Clone() const;

  virtual void AppendVars(set<var_t>* vars) const { }
  virtual bool DependsOn(const map<var_t,type_t>& vars) const { return false; }
  virtual void AppendToString(string* s) const { }
  virtual bool IsConcrete() const { return true; }

  // Convert to Yices.
  virtual yices_expr bit_blast(yices_context ctx) const;

  // Serialization.
  static SymbolicExpr* Parse(istream& s) { return NULL; }
  virtual void Serialize(string* s) const { }

  // Factory methods for constructing symbolic expressions.
  static SymbolicExpr* NewConcreteExpr(type_t ty, value_t val);

  static SymbolicExpr* NewUnaryExpr(type_t ty, value_t val,
                                    ops::unary_op_t op, SymbolicExpr* e);

  static SymbolicExpr* NewBinaryExpr(type_t ty, value_t val,
                                     ops::binary_op_t op,
                                     SymbolicExpr* e1, SymbolicExpr* e2);

  static SymbolicExpr* NewCompareExpr(type_t ty, value_t val,
                                      ops::compare_op_t op,
                                      SymbolicExpr* e1, SymbolicExpr* e2);

  static SymbolicExpr* NewConstDeref(type_t ty, value_t val,
                                     const SymbolicObject& obj, addr_t addr);

  static SymbolicExpr* NewDeref(type_t ty, value_t val,
                                const SymbolicObject& obj,
                                SymbolicExpr* addr);

  static SymbolicExpr* Concatenate(SymbolicExpr* e1, SymbolicExpr* e2);

  static SymbolicExpr* ExtractByte(SymbolicExpr* e, size_t i);

  //Virtual methods for implmenting Equals
  virtual UnaryExpr* castUnaryExpr() const { return NULL; }
  virtual BinaryExpr* castBinaryExpr() const { return NULL; }
  virtual DerefExpr* castDerefExpr() const { return NULL; }
  virtual CompareExpr* castCompareExpr() const { return NULL; }
  virtual BasicExpr* castBasicExpr() const { return NULL; }

  //Equals
  virtual bool Equals(const SymbolicExpr &e) const { return false; }

  // Accessors.
  value_t value() const { return value_; }
  size_t size() const { return size_; }

 protected:
  // Constructor for sub-classes.
  SymbolicExpr(size_t size, value_t value)
    : value_(value), size_(size) { }

 private:
  const value_t value_;
  const size_t size_;
};

}  // namespace crest

#endif  // BASE_SYMBOLIC_EXPRESSION_H__
