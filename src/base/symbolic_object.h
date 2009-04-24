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

#include <utility>
#include <vector>

#include "base/symbolic_object.h"

#include "base/basic_types.h"
#include "base/symbolic_memory.h"

namespace crest {

class SymbolicExpr;

class SymbolicObject {
 public:
  SymbolicObject(addr_t start, size_t size);
  SymbolicObject(const SymbolicObject& o);
  ~SymbolicObject();

  SymbolicExpr* read(addr_t addr, type_t ty, value_t val) const;

  void write(SymbolicExpr* sym_addr, addr_t addr,
             SymbolicExpr* e, type_t ty, value_t val);

  addr_t start() { return start_; }
  addr_t end() { return start_ + size_; }
  size_t size() { return size_; }

 private:
  typedef std::pair<SymbolicExpr*,SymbolicExpr*> Write;

  const addr_t start_;
  const size_t size_;

  SymbolicMemory mem_;
  std::vector<Write> writes_;
};

} // namespace crest

#endif // BASE_SYMBOLIC_OBJECT_H__
