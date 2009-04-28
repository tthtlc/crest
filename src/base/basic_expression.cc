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

#include "base/basic_expression.h"

#include <yices_c.h>

namespace crest {

BasicExpr::BasicExpr(size_t size, value_t val, var_t var)
  : SymbolicExpr(size, val), var_(var) { }

BasicExpr* BasicExpr::Clone() const {
  return new BasicExpr(size(), value(), var_);
}

void BasicExpr::AppendVars(set<var_t>* vars) const {
  vars->insert(var_);
}

bool BasicExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return (vars.find(var_) != vars.end());
}

void BasicExpr::AppendToString(string* s) const {
  char buff[32];
  sprintf(buff, "x%u", var_);
  s->append(buff);
}

yices_expr BasicExpr::BitBlast(yices_context ctx) const {
  char buff[32];
  sprintf(buff, "x%u", var_);
  yices_var_decl decl = yices_get_var_decl_from_name(ctx, buff);
  return yices_mk_var_from_decl(ctx, decl);
}

void BasicExpr::Serialize(string* s) const {
  s->append((char*)var_, sizeof(var_t));
}

bool BasicExpr::Equals(const SymbolicExpr &e) const {
  const BasicExpr* b = e.CastBasicExpr();
  return (b != NULL) && (var_ == b->var_);
}

}  // namespace crest
