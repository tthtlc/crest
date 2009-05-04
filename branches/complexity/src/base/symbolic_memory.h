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

#include <ext/hash_map>
#include <yices_c.h>

#include "base/basic_types.h"

using std::string;

namespace crest {

class Slab;
class SymbolicExpr;

class SymbolicMemory {
 public:
  SymbolicMemory();
  SymbolicMemory(const SymbolicMemory& m);
  ~SymbolicMemory();

  // NOTE: Transfers ownership of the returned object to the caller.
  //
  // NOTE: This must return some special kind of expression for
  // representing structures for which some of the bytes are
  // symbolic.  (And, when ty == types::STRUCT, then val is the size
  // of the structure, in bytes.)
  SymbolicExpr* read(addr_t addr, type_t ty, value_t val) const;

  // NOTE: Transfers ownership of 'e' (which must not be NULL) to this object.
  void write(addr_t addr, SymbolicExpr* e);

  void concretize(addr_t addr, size_t n);

  void Serialize(string *s) const;

  yices_expr BitBlast(yices_context ctx, addr_t addr);

  // For debugging.
  void Dump() const;

 private:
  class Slab {
   public:
    Slab();
    Slab(const Slab& slab);
    ~Slab();
    inline SymbolicExpr* read(addr_t addr, size_t n, value_t val) const;
    inline void write(addr_t addr, size_t n, SymbolicExpr* e);

    static const size_t kSlabCapacity = 8;
    static const size_t kOffsetMask = kSlabCapacity - 1;
    static const size_t kAddrMask = ~kOffsetMask;

    // For debugging.
    void Dump(addr_t addr) const;

   private:
    SymbolicExpr* slots_[kSlabCapacity];
  };

  __gnu_cxx::hash_map<addr_t, Slab> mem_;
};

}

#endif // BASE_SYMBOLIC_MEMORY_H__
