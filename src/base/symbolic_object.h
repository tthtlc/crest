// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

// TODO: Implement Equals.

#ifndef BASE_SYMBOLIC_OBJECT_H__
#define BASE_SYMBOLIC_OBJECT_H__

#include <utility>
#include <vector>

#include "base/basic_types.h"
#include "base/symbolic_expression.h"
#include "base/symbolic_memory.h"

namespace crest {

class SymbolicExpr;

class SymbolicObject {
 public:
  SymbolicObject(addr_t start, size_t size);
  SymbolicObject(const SymbolicObject& o);
  SymbolicObject(addr_t start, size_t size, SymbolicMemory mem);
  ~SymbolicObject();

  SymbolicExpr* read(addr_t addr, type_t ty, value_t val) const;

  void write(SymbolicExpr* sym_addr, addr_t addr, SymbolicExpr* e);

  void concretize(SymbolicExpr* sym_addr, addr_t addr, size_t n);

  bool Equals(const SymbolicObject& o) const { return false; }

  void Serialize(string *s) const;

  static SymbolicObject* Parse(istream &s);

  yices_expr BitBlast(yices_context ctx, addr_t concrete_address) const;

  addr_t start() const { return start_; }
  addr_t end() const { return start_ + size_; }
  size_t size() const { return size_; }

 private:
  bool ParseInternal(istream &s);

  typedef std::pair<SymbolicExpr*,SymbolicExpr*> Write;

  const addr_t start_;
  const size_t size_;

  SymbolicMemory mem_;
  std::vector<Write> writes_;
};

} // namespace crest

#endif // BASE_SYMBOLIC_OBJECT_H__
