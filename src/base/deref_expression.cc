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
#include <stdlib.h>
#include <yices_c.h>

#include "base/deref_expression.h"
#include "base/symbolic_object.h"

namespace crest {

DerefExpr::DerefExpr(SymbolicExpr *c, SymbolicObject *o, size_t s, value_t v)
  : SymbolicExpr(s,v), object_(o), addr_(c),
    concrete_bytes_(new unsigned char[o->size()])
{
  // Copy bytes from the program.
  memcpy((void*)concrete_bytes_, (void*)addr_, o->size());
}

DerefExpr::DerefExpr(const DerefExpr& de)
  : SymbolicExpr(de.size(), de.value()),
    object_(new SymbolicObject(*de.object_)), addr_(de.addr_->Clone()),
    concrete_bytes_(new unsigned char[de.object_->size()])
{
  // Copy bytes from other DerefExpr.
  memcpy((void*)concrete_bytes_, de.concrete_bytes_, object_->size());
}

DerefExpr::~DerefExpr() {
  delete object_;
  delete addr_;
  delete concrete_bytes_;
}

DerefExpr* DerefExpr::Clone() const {
  return new DerefExpr(*this);
}

void DerefExpr::AppendVars(set<var_t>* vars) const {
  assert(false);
}

bool DerefExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return true;
}

void DerefExpr::AppendToString(string *s) const {
  s->append(" (*?)");
}

void DerefExpr::Serialize(string *s) const {
  //TODO
}

yices_expr DerefExpr::BitBlast(yices_context ctx) const {
  assert(false);
  // TODO
}

bool DerefExpr::Equals(const SymbolicExpr& e) const {
  const DerefExpr* d = e.CastDerefExpr();
  return ((d != NULL)
          && addr_->Equals(*d->addr_)
          && object_->Equals(*d->object_)
          && !memcmp(concrete_bytes_, d->concrete_bytes_, object_->size()));
}

}  // namespace crest

