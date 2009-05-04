// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include <algorithm>
#include <utility>
#include <assert.h>

#include "base/symbolic_memory.h"
#include "base/symbolic_expression.h"

using std::make_pair;
using std::min;
using __gnu_cxx::hash_map;

namespace crest {

const size_t SymbolicMemory::Slab::kSlabCapacity;
const size_t SymbolicMemory::Slab::kOffsetMask;
const size_t SymbolicMemory::Slab::kAddrMask;

SymbolicMemory::Slab::Slab() {
  for (size_t i = 0; i < kSlabCapacity; i++) {
    slots_[i] = NULL;
  }
}


SymbolicMemory::Slab::Slab(const Slab& slab) {
  for (size_t i = 0; i < kSlabCapacity; i++) {
    if (slab.slots_[i] != NULL) {
      slots_[i] = slab.slots_[i]->Clone();
    } else {
      slots_[i] = NULL;
    }
  }
}

SymbolicMemory::Slab::Slab(SymbolicExpr** slots) {
  for(size_t i = 0; i < kSlabCapacity; i++)
	slots_[i] = slots[i];
}

SymbolicMemory::Slab::~Slab() {
  for (size_t i = 0; i < kSlabCapacity; i++) {
    delete slots_[i];
  }
}


SymbolicExpr* SymbolicMemory::Slab::read(addr_t addr,
                                         size_t n,
                                         value_t val) const {
  size_t i = addr & kOffsetMask;

  // Assumption: addr (and i) is n-aligned.

  { // See if we are reading part of a larger expression.
    size_t j = i;
    while ((j != 0) && (slots_[j] == NULL)) {
      j = j & (j - 1);  // Zero out the least-significant 1 bit.
    }

    if ((slots_[j] != NULL)                // found an expression,
        && (slots_[j]->size() > n)         // the expression is larger,
        && (j + slots_[j]->size() > i)) {  // and our read overlaps

      // Extract the bytes out of the expression.
      return SymbolicExpr::ExtractBytes(slots_[j]->Clone(), i - j, n);
    }
  }

  { // We are reading zero or more expressions of size <= n.
    SymbolicExpr* ret = NULL;
    size_t j = 0;
    do {
      // Is the next piece of the read symbolic?
      if (slots_[i + j] != NULL) {
        // Yes -- extend the read.
        if (ret == NULL) {
          ret = slots_[i + j]->Clone();
        } else {
          ret = SymbolicExpr::Concatenate(ret, slots_[i + j]->Clone());
        }

      } else {
        // Otherwise, the next piece is concrete.
        while ((++j < n) && (slots_[i + j] == NULL)) ;
        if (ret == NULL) {
          if (j == n) return NULL;  // Whole read is concrete.
          ret = SymbolicExpr::ExtractBytes(n, val, 0, j);
        } else {
          SymbolicExpr* tmp =
            SymbolicExpr::ExtractBytes(n, val, ret->size(), j - ret->size());
          ret = SymbolicExpr::Concatenate(ret, tmp);
        }
      }

      j = ret->size();
    } while (j < n);

    return ret;
  }
}


void SymbolicMemory::Slab::write(addr_t addr, size_t n, SymbolicExpr* e) {
  size_t i = addr & kOffsetMask;
  // Assumption: addr (and i) is n-aligned.

  { // See if we are overwriting part of a larger expression.
    size_t j = i;
    while ((j != 0) && (slots_[j] == NULL)) {
      j = j & (j - 1);  // Zero out the least-significant 1 bit.
    }

    if ((slots_[j] != NULL)                // found an expression,
        && (slots_[j]->size() > n)         // the expression is larger,
        && (j + slots_[j]->size() > i)) {  // and our write overlaps

      // Split the larger expression into pieces of size n.
      SymbolicExpr* tmp = slots_[j];
      slots_[j] = SymbolicExpr::ExtractBytes(tmp, 0, n);
      for (size_t k = n; k < tmp->size(); k += n) {
        slots_[j + k] = SymbolicExpr::ExtractBytes(tmp->Clone(), k, n);
      }
    }
  }

  // Delete any expressions we overwrite.
  // (All such expressions now have size <= n.)
  for (size_t j = 0; j < n; j++) {
    delete slots_[i + j];
    slots_[i + j] = NULL;
  }

  // Write the new expression.
  slots_[i] = e;
}

void SymbolicMemory::Slab::Serialize(string *s) const {
  for (size_t i = 0; i < kSlabCapacity; i++)
	slots_[i]->Serialize(s);
}

SymbolicMemory::Slab* SymbolicMemory::Slab::Parse(istream &s) {
  SymbolicExpr *slots[kSlabCapacity];
  for (size_t i = 0; i < kSlabCapacity; i++)
	slots[i] = SymbolicExpr::Parse(s);
  return new SymbolicMemory::Slab(slots);
}

void SymbolicMemory::Slab::Dump(addr_t addr) const {
  string s;

  for (size_t i = 0; i < kSlabCapacity; i++) {
    if (slots_[i] != NULL) {
      s.clear();
      slots_[i]->AppendToString(&s);
      fprintf(stderr, "*%lu (%zu): %lld [ %s ]\n",
              addr + i, slots_[i]->size(), slots_[i]->value(), s.c_str());
    }
  }
}


SymbolicMemory::SymbolicMemory() { }


SymbolicMemory::SymbolicMemory(const SymbolicMemory& m)
  : mem_(m.mem_) { }

SymbolicMemory::~SymbolicMemory() { }


void SymbolicMemory::Dump() const {
  hash_map<addr_t,Slab>::const_iterator it;
  for (it = mem_.begin(); it != mem_.end(); ++it) {
    it->second.Dump(it->first);
  }
}


SymbolicExpr* SymbolicMemory::read(addr_t addr, type_t ty, value_t val) const {
  // For now, ignore structs.
  if (ty == types::STRUCT)
    return NULL;

  // TODO: Have to deal with 8-byte long longs that are only aligned
  // to 4 bytes.

  hash_map<addr_t,Slab>::const_iterator it = mem_.find(addr & Slab::kAddrMask);
  if (it == mem_.end())
    return NULL;

  size_t n = kSizeOfType[ty];
  return it->second.read(addr, n, val);
}


void SymbolicMemory::write(addr_t addr, SymbolicExpr* e) {
  assert(e != NULL);

  // TODO: Have to deal with 8-byte long longs that are only aligned
  // to 4 bytes.

  hash_map<addr_t,Slab>::iterator it = mem_.find(addr & Slab::kAddrMask);
  if (it == mem_.end()) {
    it = (mem_.insert(make_pair(addr & Slab::kAddrMask, Slab()))).first;
  }

  it->second.write(addr, e->size(), e);
}


void SymbolicMemory::concretize(addr_t addr, size_t n) {
  assert(n > 0);

  // No idea what kind of alignment we might have here (because of
  // structs).  Also, might have sizes that are not powers of two.

  int left = static_cast<int>(n);
  do {
    // Look up the slab.
    hash_map<addr_t,Slab>::iterator it = mem_.find(addr & Slab::kAddrMask);
    if (it == mem_.end()) {
      // Nothing to concretize in this (missing) slab.
      left -= Slab::kSlabCapacity - (addr & Slab::kOffsetMask);
      addr = (addr & Slab::kAddrMask) + Slab::kSlabCapacity;
      continue;
    }

    // Compute the largest size we can write (i.e. concretize) given
    // alignment constraints.
    size_t sz = min((size_t)(addr & -addr), Slab::kSlabCapacity);
    while (sz > n) {
      sz >>= 1;
    }

    // Concretize.
    it->second.write(addr, sz, NULL);

    addr += sz;
    left -= sz;
  } while (left > 0);
}


void SymbolicMemory::Serialize(string *s) const {
  //Format is :mem_size() | i | mem_[i]
  size_t mem_size = mem_.size();
  s->append((char*)&mem_size, sizeof(size_t));

  //Now write the memory contents
  for(hash_map<addr_t, Slab>::const_iterator it = mem_.begin(); it != mem_.end(); it++) {
	  s->append((char*)&(it->first), sizeof(addr_t));
	  (it->second).Serialize(s);
  }

}

void SymbolicMemory::Parse(istream &s) {
  size_t mem_size;
  addr_t addr;
  SymbolicMemory::Slab *slab;
  
  s.read((char*)&mem_size, sizeof(size_t));

  for(size_t i = 0; i < mem_size; i++) {
	s.read((char*)&addr, sizeof(addr_t));
	slab = SymbolicMemory::Slab::Parse(s);
	this->mem_[addr] = *slab;
  }
  // TODO: We should be able to call something like this...
  // return new SymbolicMemory(mem);
}

yices_expr SymbolicMemory::BitBlast(yices_context ctx, addr_t addr) {
  /*
  SymbolicExpr* expr = mem_[addr];
  return expr->BitBlast(ctx);
  */
  return NULL;
}

}  // namespace crest
