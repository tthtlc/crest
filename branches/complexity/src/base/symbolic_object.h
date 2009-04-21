// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#ifndef BASE_SYMBOLIC_OBJECT_H__
#define BASE_SYMBOLIC_OBJECT_H__

#include "base/basic_types.h"

namespace crest {

class SymbolicExpression;

class SymbolicObject {
 public:
  SymbolicObject(addr_t start, size_t size) { }
  SymbolicObject(const SymbolicObject& o) { }

  SymbolicExpr* read(addr_t addr, type_t ty, value_t val) const {
    return NULL;
  }

  void write(const SymbolicExpr* sym_addr, addr_t addr,
             const SymbolicExpr* e, type_t ty, value_t val) { }

 private:
};

} // namespace crest

#endif // BASE_SYMBOLIC_OBJECT_H__
