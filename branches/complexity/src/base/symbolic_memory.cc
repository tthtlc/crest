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


SymbolicMemory::~SymbolicMemory() {
  hash_map<addr_t,SymbolicExpr*>::iterator it;
  for (it = mem_.begin(); it != mem_.end(); ++it) {
    delete it->second;
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
      hash_map<addr_t,SymbolicExpr*>::const_iterator it = mem_.find(n - i - 1);
      bytes[i] = (it == mem_.end()) ? NULL : it->second;
      symbolic = symbolic || (bytes[i] != NULL);
    }
  } else /* big-endian */ {
    for (size_t i = 0; i < n; i++) {
      hash_map<addr_t,SymbolicExpr*>::const_iterator it = mem_.find(i);
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
      tmp = new SymbolicExpr(*bytes[n-i-1]);
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
      mem_[addr + i] = SymbolicExpr::ExtractByte(*e, n - i + 1);
    }
  } else /* big-endian */ {
    for (size_t i = 0; i < n; i++) {
      mem_[addr + i] = SymbolicExpr::ExtractByte(*e, i);
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

}  // namespace crest
