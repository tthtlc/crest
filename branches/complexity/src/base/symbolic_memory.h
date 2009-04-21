// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#ifndef BASE_SYMBOLIC_MEMORY_H__
#define BASE_SYMBOLIC_MEMORY_H__

namespace crest {

class SymbolicExpression;

class SymbolicMemory {
 public:

  // NOTE: Transfers ownership of the returned object to the caller.
  //
  // NOTE: This must return some special kind of expression for
  // representing structures for which some of the bytes are
  // symbolic.  (And, when ty == types::STRUCT, then val is the size
  // of the structure, in bytes.)
  //
  // NOTE: The 'val' parameter is somewhat less weird if the resulting
  // symbolic expression must contain its own concrete value.
  SymbolicExpr* read(addr_t addr, type_t ty, value_t val) {
    return NULL;
  }

  // NOTE: Transfers ownership of 'e' to this object.
  //
  // TODO: Remove 'ty' parameter if expression contains its own type.
  void write(addr_t addr, type_t ty, SymbolicExpr* e) { }

  void concretize(addr_t addr, size_t n) { }
};

}

#endif // BASE_SYMBOLIC_MEMORY_H__