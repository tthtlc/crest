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
#include "base/deref_expression.h"

using namespace __gnu_cxx;

namespace crest {

DerefExpr::DerefExpr(SymbolicExpr *c, SymbolicObject *o, size_t s, value_t v) :
  SymbolicExpr(v,s), object_(o), symbolic_addr_(c) {
  concrete_bytes_ = new unsigned char[o->size()];
}

DerefExpr::~DerefExpr() { }

size_t DerefExpr::DerefExpr::Size() {
  return 0;
}

void DerefExpr::AppendVars(set<var_t>* vars) { }

bool DerefExpr::DependsOn(const map<var_t,type_t>& vars) {
  return false;
}

void DerefExpr::AppendToString(string *s) {
  s->append(" (*");
  s->append(")");
}

bool DerefExpr::IsConcrete() {
  return false;
}

bool DerefExpr::operator==(DerefExpr &e) {
  return false;
}

void DerefExpr::bit_blast(yices_expr &e, yices_context &ctx, map<var_t, yices_var_decl> &x_decl) {
  // TODO
}

}  // namespace crest

