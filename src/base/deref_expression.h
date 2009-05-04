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

// TODO: Implement Parse and Serialize

#ifndef DEREF_EXPRESSION_H__
#define DEREF_EXPRESSION_H__

#include "base/basic_types.h"
#include "base/symbolic_expression.h"

namespace crest {

class DerefExpr : public SymbolicExpr {
 public:
  DerefExpr(SymbolicExpr* addr, SymbolicObject* o, size_t size, value_t val);
  DerefExpr(const DerefExpr& de);
  ~DerefExpr();

  DerefExpr* Clone() const;

  void AppendVars(set<var_t>* vars) const;
  bool DependsOn(const map<var_t,type_t>& vars) const;
  void AppendToString(string *s) const;

  bool IsConcrete() const { return false; }

  yices_expr BitBlast(yices_context ctx) const;

  const DerefExpr* CastDerefExpr() const { return this; }
  void Serialize(string* s) const;
  bool Equals(const SymbolicExpr &e) const;

 private:
  // The symbolic object corresponding to the dereference.
  const SymbolicObject *object_;

  // A symbolic expression representing the symbolic address of this deref.
  const SymbolicExpr *addr_;

  const unsigned char* concrete_bytes_;

  inline value_t ConcreteValueFromBytes(size_t i, size_t size_) const;
};

}  // namespace crest

#endif  // DEREF_EXPRESSION_H__
