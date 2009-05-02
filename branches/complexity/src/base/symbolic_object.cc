// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include<assert.h>
#include "base/symbolic_object.h"

#include "base/symbolic_expression.h"
#include "base/symbolic_memory.h"

using namespace std;

namespace crest {

SymbolicObject::SymbolicObject(addr_t start, size_t size)
  : start_(start), size_(size), writes_() { }

SymbolicObject::SymbolicObject(const SymbolicObject &obj)
  : start_(obj.start_), size_(obj.size_),
    mem_(obj.mem_), writes_(obj.writes_)
{
  for (vector<Write>::iterator it = writes_.begin(); it != writes_.end(); ++it) {
    it->first = it->first->Clone();
    it->second = it->second->Clone();
  }
}

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
    return SymbolicExpr::NewConstDerefExpr(ty, val, *this, addr);
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

void SymbolicObject::Serialize(string* s) const {
  //Format is: start_ | size_ | mem_
  //Not keeping tracks of symbolic writes
  s->append((char*)&start_, sizeof(addr_t));
  s->append((char*)&size_, sizeof(size_t));
  //mem_.Serialize(s);
}

SymbolicObject* SymbolicObject::Parse(istream& s) {
  addr_t st;
  size_t si;

  s.read((char*)&st, sizeof(addr_t));
  if(s.fail()) return NULL;
  s.read((char*)&si, sizeof(size_t));
  if(s.fail()) return NULL;

  return new SymbolicObject(st, si);
}

yices_expr SymbolicObject::BitBlast(yices_context ctx, addr_t concrete_address) const {
	assert(start_ <= concrete_address && start_+size_ >= concrete_address);
	SymbolicMemory* m = new SymbolicMemory(mem_);
	return m->BitBlast(ctx, concrete_address - start_);
}
}  // namespace crest
