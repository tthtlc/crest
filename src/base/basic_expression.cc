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
 * Author: Sudeep juvekar (sjuvekar@eecs.berkeley.edu)
 * 4/17/09
 */
#include <assert.h>
#include <yices_c.h>
#include "base/basic_expression.h"

namespace crest {

BasicExpr::BasicExpr(var_t v) : variable_(v) {
  sprintf(yices_type_, "(bitvector 0)");
}

BasicExpr::BasicExpr(size_t s, value_t val, var_t var) :
  SymbolicExpr(val,s), variable_(var) {
  sprintf(yices_type_, "(bitvector %u)", size_in_bytes_);
}

size_t BasicExpr::Size() { return 1; }

void BasicExpr::AppendVars(set<var_t>* vars) { vars->insert(variable_); }

bool BasicExpr::DependsOn(const map<var_t,type_t>& vars) {
  if (vars.find(variable_) != vars.end())
    return true;
  return false;
}

void BasicExpr::AppendToString(string* s) {
  char buff[32];
  sprintf(buff, "x%u", variable_);
  s->append(buff);
}

bool BasicExpr::IsConcrete() {
  if (variable_  == kMaxValue[types::U_INT]) return true;
  return false;
}

bool BasicExpr::operator==(BasicExpr &e) {
  return variable_ == e.variable_;
}

void BasicExpr::bit_blast(yices_expr &e, yices_context &ctx, map<var_t,yices_var_decl> &x_decl) {
  if (variable_ == kMaxValue[types::U_INT]) {
    e = yices_mk_num(ctx, value_);
  } else {
    char buff[32];
    sprintf(buff, "x%u", variable_);
    yices_type bv_ty = yices_mk_type(ctx, yices_type_);
    yices_var_decl int_decl = yices_mk_var_decl(ctx, buff, bv_ty);
    e = yices_mk_var_from_decl(ctx, int_decl);
    x_decl[variable_] = int_decl;
  }
}

}  // namespace crest
