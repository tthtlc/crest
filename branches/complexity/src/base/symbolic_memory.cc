// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include "base/symbolic_memory.h"

#include "base/symbolic_expression.h"

using namespace __gnu_cxx;

namespace crest {

SymbolicMemory::SymbolicMemory() { }

SymbolicMemory::SymbolicMemory(const SymbolicMemory& m) : mem_(m.mem_) {
  hash_map<addr_t,SymbolicExpr*>::iterator it;
  for (it = mem_.begin(); it != mem_.end(); ++it) {
    it->second = it->second->Clone();
  }
}


SymbolicMemory::~SymbolicMemory() {
  hash_map<addr_t,SymbolicExpr*>::iterator it;
  for (it = mem_.begin(); it != mem_.end(); ++it) {
    delete it->second;
  }
}


void SymbolicMemory::Dump() const {
  string s;

  hash_map<addr_t,SymbolicExpr*>::const_iterator it;
  for (it = mem_.begin(); it != mem_.end(); ++it) {
    s.clear();
    it->second->AppendToString(&s);
    fprintf(stderr, "*%lu (%zu): %lld [ %s ]\n", it->first,
            it->second->size(), it->second->value(), s.c_str());
  }
}


SymbolicExpr* SymbolicMemory::read(addr_t addr, type_t ty, value_t val) const {
  // For now, ignore structs.
  if (ty == types::STRUCT)
    return NULL;

  // Read each requested byte.
  size_t n = kSizeOfType[ty];
  bool symbolic = false;
  SymbolicExpr* bytes[8];
  if (true /* little-endian */) {
    for (size_t i = 0; i < n; i++) {
      hash_map<addr_t,SymbolicExpr*>::const_iterator it;
      it = mem_.find(addr + n - i - 1);
      bytes[i] = (it == mem_.end()) ? NULL : it->second;
      symbolic = symbolic || (bytes[i] != NULL);
    }
  } else /* big-endian */ {
    for (size_t i = 0; i < n; i++) {
      hash_map<addr_t,SymbolicExpr*>::const_iterator it;
      it = mem_.find(addr + i);
      bytes[i] = (it == mem_.end()) ? NULL : it->second;
      symbolic = symbolic || (bytes[i] != NULL);
    }
  }

  if (!symbolic) {
    return NULL;
  }

  // Construct a symbolic expression to return.
  SymbolicExpr* ret = NULL;
  for (size_t i = 0; i < n; i++, val >>= 8) {
    // Construct expression for i-th lowest-order byte.
    SymbolicExpr* tmp = NULL;
    if (bytes[n-i-1] == NULL) {
      tmp = SymbolicExpr::NewConcreteExpr(types::U_CHAR, val & 0xFF);
    } else {
      tmp = bytes[n-i-1]->Clone();
    }

    // Add byte into concatenation.
    if (ret == NULL) {
      ret = tmp;
    } else {
      ret = SymbolicExpr::Concatenate(tmp, ret);
    }
  }

  return ret;
}


void SymbolicMemory::write(addr_t addr, type_t ty, SymbolicExpr* e) {
  // For now, ignore structs.
  if (ty == types::STRUCT)
    return;

  // Special case write of single byte.
  size_t n = kSizeOfType[ty];
  if (n == 1) {
    mem_[addr] = e;
    return;
  }

  // Extract and write each byte.
  if (true /* little-endian */) {
    for (size_t i = 0; i < n; i++) {
      // TODO: Leaks memory.
      mem_[addr + i] = SymbolicExpr::ExtractByte(e->Clone(), n - i - 1);
    }
  } else /* big-endian */ {
    for (size_t i = 0; i < n; i++) {
      // TODO: Leaks memory.
      mem_[addr + i] = SymbolicExpr::ExtractByte(e->Clone(), i);
    }
  }

  delete e;
}

void SymbolicMemory::concretize(addr_t addr, size_t n) {
  for (size_t i = 0; i < n; i++) {
    hash_map<addr_t,SymbolicExpr*>::iterator it = mem_.find(addr + i);
    if (it != mem_.end()) {
      delete it->second;
      mem_.erase(it);
    }
  }
}

void SymbolicMemory::Serialize(string *s) const {
  //Format is :mem_size() | i | mem_[i]
  unsigned int mem_size = sizeof(size_t);
  char buff[8*mem_size];
  sprintf(buff, "%u",mem_.size());
  s->append(buff, mem_size);

  //Now write the memory contents
  for(hash_map<addr_t, SymbolicExpr*>::const_iterator it = mem_.begin(); it != mem_.end(); it++) {
	  s->append((char*)(it->first), sizeof(addr_t));
	  (it->second)->Serialize(s);
  }

}

yices_expr SymbolicMemory::BitBlast(yices_context ctx, addr_t addr) {
  SymbolicExpr* expr = mem_[addr];
  return expr->BitBlast(ctx);
}
}  // namespace crest
