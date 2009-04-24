// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include "base/symbolic_object.h"

#include "base/symbolic_expression.h"
#include "base/symbolic_memory.h"

using namespace std;

namespace crest {

SymbolicObject::SymbolicObject(addr_t start, size_t size)
  : start_(start), size_(size), writes_(4) { }


SymbolicObject::~SymbolicObject() {
  for (vector<Write>::iterator it = writes_.begin(); it != writes_.end(); ++it) {
    delete it->first;
    delete it->second;
  }
}

SymbolicExpr* SymbolicObject::read(addr_t addr, type_t ty, value_t val) const {
  if (writes_.size() == 0) {
    // No symbolic writes yes, so normal read.
    return mem_.read(addr, ty, val);
  } else {
    // There have been symbolic writes, so return a deref.
    return SymbolicExpr::NewConstDeref(*this, addr, ty, val);
  }
}


void SymbolicObject::write(SymbolicExpr* sym_addr, addr_t addr,
                           SymbolicExpr* e, type_t ty, value_t val) {

  if ((writes_.size() == 0) && ((sym_addr == NULL) || sym_addr->IsConcrete())) {
      // Normal write.
      mem_.write(addr, ty, e);
      delete e;

  } else {
    // There have been symbolic writes, so record this write.
    if (sym_addr == NULL) {
      sym_addr = SymbolicExpr::NewConcreteExpr(types::U_LONG, addr);
    }
    if (e == NULL) {
      e = SymbolicExpr::NewConcreteExpr(ty, val);
    }
    writes_.push_back(make_pair(sym_addr, e));
  }
}



}  // namespace crest
