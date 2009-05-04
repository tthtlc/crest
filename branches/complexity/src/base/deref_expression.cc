// Copyright (c) 2009, Jacob Burnim (jburnim@cs.berkeley.edu)
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
#include <stdlib.h>
#include <yices_c.h>

#include "base/deref_expression.h"
#include "base/symbolic_object.h"

namespace crest {

DerefExpr::DerefExpr(SymbolicExpr *c, SymbolicObject *o, unsigned char* bytes,
                     size_t s, value_t v)
  : SymbolicExpr(s,v), object_(o), addr_(c), concrete_bytes_(bytes) { }


DerefExpr::DerefExpr(const DerefExpr& de)
  : SymbolicExpr(de.size(), de.value()),
    object_(new SymbolicObject(*de.object_)), addr_(de.addr_->Clone()),
    concrete_bytes_(new unsigned char[de.object_->size()])
{
  // Copy bytes from other DerefExpr.
  memcpy((void*)concrete_bytes_, de.concrete_bytes_, object_->size());
}


DerefExpr::~DerefExpr() {
  delete object_;
  delete addr_;
  delete concrete_bytes_;
}

DerefExpr* DerefExpr::Clone() const {
  return new DerefExpr(*this);
}

void DerefExpr::AppendVars(set<var_t>* vars) const {
  assert(false);
}

bool DerefExpr::DependsOn(const map<var_t,type_t>& vars) const {
  return true;
}

void DerefExpr::AppendToString(string *s) const {
  s->append(" (*?)");
}

void DerefExpr::Serialize(string *s) const {
  SymbolicExpr::Serialize(s, kDerefNodeTag);
  object_->Serialize(s);
  addr_->Serialize(s);
  s->append((char*)concrete_bytes_, object_->size());
}

value_t DerefExpr::ConcreteValueFromBytes(size_t i, size_t size_) const {
  //Read size_ bytes at offset i from concrete_bytes_
  size_t concrete_value = 0;
  for(size_t j = 0; j < size_; j++) {
	char c = concrete_bytes_[i+j];

#ifdef BIG_ENDIAN
  concrete_value = concrete_value>>(8*sizeof(char)) | c<<(8*(size_-j-1)*sizeof(char));
#else
  concrete_value = conconcrete_value<<(8*sizeof(char)) | c;
#endif

  }
  return concrete_value;
}

yices_expr DerefExpr::BitBlast(yices_context ctx) const {
  // Create a yices_function_type representing a function from bit_vector to bit_vector
  size_t size_ = size();
  size_t mem_length = object_->size() / size_;

  //Naming the uninterpreted function
  char c[32];
  sprintf(c, "f%d",(int)this);

  //Bit-blast the address
  yices_expr args_yices_f[1] = { addr_->BitBlast(ctx) };
  // Assert that address is equal to one in the domain
  yices_expr* t = new yices_expr[mem_length];

  yices_type input_type[1] = { yices_mk_bitvector_type(ctx, size_*8) };
  yices_type output_type = yices_mk_bitvector_type(ctx, size_*8);
  yices_type yices_function = yices_mk_function_type(ctx, input_type, 1, output_type);

  yices_var_decl fdecl = yices_mk_var_decl(ctx, c, yices_function);
  yices_expr f = yices_mk_var_from_decl(ctx, fdecl);

  SymbolicExpr* exp = NULL;

  // Populate the function and assert
  for(size_t i = 0; i < mem_length; i++) {

	value_t concrete_value = this->ConcreteValueFromBytes(i*size_, size_);
	exp = object_->read(object_->start() + i * size_, types::U_INT, concrete_value);
	if(exp == NULL) {
		exp = SymbolicExpr::NewConcreteExpr(types::U_INT, concrete_value);
	}
	yices_expr expression_at_i = exp->BitBlast(ctx);
	yices_expr bit_vector_i[1] = { yices_mk_bv_constant(ctx, size_*8, i * size_ + object_->start()) };
	yices_expr function_application = yices_mk_app(ctx, f, bit_vector_i, 1);
	yices_assert(ctx, yices_mk_eq(ctx, function_application, expression_at_i));
	t[i] = yices_mk_eq(ctx, args_yices_f[0], bit_vector_i[0]);
  }

  //Assert that sumbolic address is equal to at one of the values in domain
  yices_assert(ctx, yices_mk_or(ctx, t, mem_length));
  //Return the application of the function to addr_
  return yices_mk_app(ctx, f, args_yices_f, 1);

}

bool DerefExpr::Equals(const SymbolicExpr& e) const {
  const DerefExpr* d = e.CastDerefExpr();
  return ((d != NULL)
          && addr_->Equals(*d->addr_)
          && object_->Equals(*d->object_)
          && !memcmp(concrete_bytes_, d->concrete_bytes_, object_->size()));
}

}  // namespace crest

