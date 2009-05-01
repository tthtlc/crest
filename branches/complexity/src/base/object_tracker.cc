// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include "base/object_tracker.h"

#include "base/symbolic_object.h"

using std::map;

namespace crest {

typedef map<addr_t,SymbolicObject*>::const_iterator EntryIt;

ObjectTracker::~ObjectTracker() {
  for (EntryIt i = objs_.begin(); i != objs_.end(); ++i) {
    delete i->second;
  }
}

void ObjectTracker::add(addr_t addr, size_t size) {
  // TODO: This could leak memory.
  objs_[addr + size] = new SymbolicObject(addr, size);
}

SymbolicObject* ObjectTracker::find(addr_t addr) const {
  EntryIt i = objs_.upper_bound(addr);

  if (i == objs_.end())
    return NULL;

  if (i->second->start() <= addr)
    return i->second;

  return NULL;
}

}  // namespace crest
