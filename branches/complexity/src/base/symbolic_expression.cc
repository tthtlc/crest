// Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
//
// This file is part of CREST, which is distributed under the revised
// BSD license.  A copy of this license can be found in the file LICENSE.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
// for details.

/***
 * Author: Sudeep juvekar (sjuvekar@eecs.berkeley.edu)
 * 4/17/09
 */
#include <assert.h>

#include <yices_c.h>

#include "base/symbolic_expression.h"
#include "base/unary_expression.h"
#include "base/binary_expression.h"
#include "base/compare_expression.h"
#include "base/deref_expression.h"
#include "base/symbolic_object.h"
#include "base/basic_expression.h"

namespace crest {

typedef map<var_t,value_t>::iterator It;
typedef map<var_t,value_t>::const_iterator ConstIt;

SymbolicExpr::~SymbolicExpr() { }

SymbolicExpr* SymbolicExpr::Clone() const {
  return new SymbolicExpr(size_, value_);
}

void SymbolicExpr::AppendToString(string* s) const {
  assert(IsConcrete());

  char buff[32];
  sprintf(buff, "%lld", value());
  s->append(buff);
}

bool SymbolicExpr::Equals(const SymbolicExpr &e) const {
  return (e.IsConcrete()
          && (value() == e.value())
          && (size() == e.size()));
}

yices_expr SymbolicExpr::BitBlast(yices_context ctx) const {
  // TODO: Implement this method for size() > sizeof(unsigned long).
  assert(size() <= sizeof(unsigned long));
  return yices_mk_bv_constant(ctx, 8*size(), (unsigned long)value());
}

SymbolicExpr* SymbolicExpr::NewConcreteExpr(type_t ty, value_t val) {
  return new SymbolicExpr(kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewUnaryExpr(type_t ty, value_t val,
                                         ops::unary_op_t op, SymbolicExpr* e) {
  return new UnaryExpr(op, e, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewBinaryExpr(type_t ty, value_t val,
                                          ops::binary_op_t op,
                                          SymbolicExpr* e1, SymbolicExpr* e2) {
  return new BinaryExpr(op, e1, e2, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewCompareExpr(type_t ty, value_t val,
                                           ops::compare_op_t op,
                                           SymbolicExpr* e1, SymbolicExpr* e2) {
  return new CompareExpr(op, e1, e2, kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewConstDeref(type_t ty, value_t val,
                                          const SymbolicObject& obj,
                                          addr_t addr) {
  return new DerefExpr(NewConcreteExpr(types::U_LONG, addr),
                       new SymbolicObject(obj), kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::NewDeref(type_t ty, value_t val,
                                     const SymbolicObject& obj,
                                     SymbolicExpr* addr) {
  return new DerefExpr(addr, new SymbolicObject(obj), kSizeOfType[ty], val);
}

SymbolicExpr* SymbolicExpr::Concatenate(SymbolicExpr *e1, SymbolicExpr *e2) {
  return new BinaryExpr(ops::CONCAT, e1, e2,
                        e1->size() + e2->size(),
                        (e1->value() << (8 * e2->size())) + e2->value());
}

SymbolicExpr* SymbolicExpr::ExtractByte(SymbolicExpr* e, size_t i) {
  // Extract i-th most significant byte.
  value_t val = (e->value() >> (e->size() - i - 1)) & 0xFF;
  SymbolicExpr* i_e = NewConcreteExpr(types::U_LONG, i);
  return new BinaryExpr(ops::EXTRACT, e, i_e,  1, val);
}

SymbolicExpr* SymbolicExpr::Parse(istream& s) {
  value_t* val = new value_t(sizeof(value_t));
  size_t* siz = new size_t(sizeof(size_t));
  var_t* var = new var_t(sizeof(var_t));
  SymbolicExpr *left = NULL, *right = NULL, *child=NULL;
  compare_op_t cmp_op_ = ops::EQ;
  binary_op_t bin_op_ = ops::ADD;
  unary_op_t un_op_ = ops::NEGATE;

  SymbolicObject *obj = NULL;
  SymbolicExpr *addr = NULL;

  s.read((char *)val, sizeof(value_t));
	  if(s.fail()) return NULL;
  s.read((char *)siz, sizeof(size_t));
	  if(s.fail()) return NULL;

  char type_ = s.get();
  switch(type_) {

  case kBasicNodeTag:
	  s.read((char*)var, sizeof(var_t));
	  if(s.fail()) return NULL;
	  return new BasicExpr(*siz, *val, *var);

  case kCompareNodeTag:
	  cmp_op_ = (compare_op_t)s.get();
	  if(s.fail()) return NULL;
	  left = Parse(s);
	  right = Parse(s);
	  return new CompareExpr(cmp_op_, left, right, *siz, *val);

  case kBinaryNodeTag:
	  bin_op_ = (binary_op_t)s.get();
	  if(s.fail()) return NULL;
	  left = Parse(s);
	  right = Parse(s);
	  return new BinaryExpr(bin_op_, left, right, *siz, *val);

  case kUnaryNodeTag:
	  un_op_ = (unary_op_t)s.get();
	  if(s.fail()) return NULL;
	  child = Parse(s);
	  return new UnaryExpr(un_op_, child, *siz, *val);

  case kDerefNodeTag:
	  obj = SymbolicObject::Parse(s);
	  if(obj == NULL) { // That means read has failed in object::Parse
		  return NULL;
	  }
	  addr = SymbolicExpr::Parse(s);
	  if(addr == NULL) { // Read has failed in expr::Parse
		  return NULL;
	  }
	  return new DerefExpr(addr, obj, *siz, *val);
  case kConstNodeTag:
	  return new SymbolicExpr(*siz, *val);

  default:
	  fprintf(stderr, "Unknown type of node: '%c'....exiting\n", type_);
	  exit(1);
  }
}

void SymbolicExpr::Serialize(string *s) const {
	SymbolicExpr::Serialize(s, kConstNodeTag);
}

void SymbolicExpr::Serialize(string *s, char c) const {
  s->append((char*)&value_, sizeof(value_t));
  s->append((char*)&size_, sizeof(size_t));
  s->push_back(c);
}

}  // namespace crest
