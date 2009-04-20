// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

#include <assert.h>
#include "base/linear_expression.h"

namespace crest {

typedef map<var_t,value_t>::iterator It;
typedef map<var_t,value_t>::const_iterator ConstIt;


LinearExpr::~LinearExpr() { }

LinearExpr::LinearExpr() : const_(0) { }

LinearExpr::LinearExpr(value_t c) : const_(c) { }

LinearExpr::LinearExpr(value_t c, var_t v) : const_(0) {
  coeff_[v] = c;
}

LinearExpr::LinearExpr(const LinearExpr& e)
  : const_(e.const_), coeff_(e.coeff_) { }


void LinearExpr::Negate() {
  const_ = -const_;
  for (It i = coeff_.begin(); i != coeff_.end(); ++i) {
    i->second = -i->second;
  }
}


void LinearExpr::AppendVars(set<var_t>* vars) const {
  for (ConstIt i = coeff_.begin(); i != coeff_.end(); ++i) {
    vars->insert(i->first);
  }
}

bool LinearExpr::DependsOn(const map<var_t,type_t>& vars) const {
  for (ConstIt i = coeff_.begin(); i != coeff_.end(); ++i) {
    if (vars.find(i->first) != vars.end())
      return true;
  }
  return false;
}


void LinearExpr::AppendToString(string* s) const {
  char buff[32];
  sprintf(buff, "(+ %lld", const_);
  s->append(buff);

  for (ConstIt i = coeff_.begin(); i != coeff_.end(); ++i) {
    sprintf(buff, " (* %lld x%u)", i->second, i->first);
    s->append(buff);
  }

  s->push_back(')');
}


void LinearExpr::Serialize(string* s) const {
  assert(coeff_.size() < 128);
  s->push_back(static_cast<char>(coeff_.size()));
  s->append((char*)&const_, sizeof(value_t));
  for (ConstIt i = coeff_.begin(); i != coeff_.end(); ++i) {
    s->append((char*)&i->first, sizeof(var_t));
    s->append((char*)&i->second, sizeof(value_t));
  }
}


bool LinearExpr::Parse(istream& s) {
  size_t len = static_cast<size_t>(s.get());
  s.read((char*)&const_, sizeof(value_t));
  if (s.fail())
    return false;

  coeff_.clear();
  for (size_t i = 0; i < len; i++) {
    var_t v;
    value_t c;
    s.read((char*)&v, sizeof(v));
    s.read((char*)&c, sizeof(c));
    coeff_[v] = c;
  }

  return !s.fail();
}


const LinearExpr& LinearExpr::operator+=(const LinearExpr& e) {
  const_ += e.const_;
  for (ConstIt i = e.coeff_.begin(); i != e.coeff_.end(); ++i) {
    It j = coeff_.find(i->first);
    if (j == coeff_.end()) {
      coeff_.insert(*i);
    } else {
      j->second += i->second;
      if (j->second == 0) {
	coeff_.erase(j);
      }
    }
  }
  return *this;
}


const LinearExpr& LinearExpr::operator-=(const LinearExpr& e) {
  const_ -= e.const_;
  for (ConstIt i = e.coeff_.begin(); i != e.coeff_.end(); ++i) {
    It j = coeff_.find(i->first);
    if (j == coeff_.end()) {
      coeff_[i->first] = -i->second;
    } else {
      j->second -= i->second;
      if (j->second == 0) {
	coeff_.erase(j);
      }
    }
  }
  return *this;
}


const LinearExpr& LinearExpr::operator+=(value_t c) {
  const_ += c;
  return *this;
}


const LinearExpr& LinearExpr::operator-=(value_t c) {
  const_ -= c;
  return *this;
}


const LinearExpr& LinearExpr::operator*=(value_t c) {
  if (c == 0) {
    coeff_.clear();
    const_ = 0;
  } else {
    const_ *= c;
    for (It i = coeff_.begin(); i != coeff_.end(); ++i) {
      i->second *= c;
    }
  }
  return *this;
}

bool LinearExpr::operator==(const LinearExpr& e) const {
  return ((const_ == e.const_) && (coeff_ == e.coeff_));
}


}  // namespace crest

