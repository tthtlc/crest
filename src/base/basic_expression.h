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
#ifndef BASIC_TYPE_H__
#define BASIC_TYPE_H__

#include <map>
#include <set>
#include <string>

#include "base/basic_types.h"
#include "base/symbolic_expression.h"
#include "base/symbolic_object.h"

using std::map;
using std::set;
using std::string;

typedef void* yices_expr;
typedef void* yices_context;

namespace crest {

class BasicExpr : public SymbolicExpr {
 public:
  BasicExpr(size_t size, value_t val, var_t var);
  ~BasicExpr() { }

  BasicExpr* Clone() const;

  void AppendVars(set<var_t>* vars) const;
  bool DependsOn(const map<var_t,type_t>& vars) const;
  void AppendToString(string* s) const;
  void Serialize(string* s) const;

  bool IsConcrete() const { return false; }

  yices_expr BitBlast(yices_context ctx) const;

  const BasicExpr* CastBasicExpr() const { return this; }

  bool Equals(const SymbolicExpr &e) const;

  // Accessor.
  var_t variable() const { return var_; }

 private:
  const var_t var_;
};

}  // namespace crest

#endif  // BASIC_TYPE_H__
