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
 * Author: Sudeep juvekar (sjuvekar@eecs.berkeley.edu
 * 4/17/09
 */
#include <assert.h>
#include "base/symbolic_expression.h"

namespace crest {

typedef map<var_t,value_t>::iterator It;
typedef map<var_t,value_t>::const_iterator ConstIt;


SymbolicExpr::~SymbolicExpr() { }

SymbolicExpr::SymbolicExpr() {
	expr_ = new LinearExpr(0);
	node_type_ = LINEAR;
}

SymbolicExpr::SymbolicExpr(value_t c) {
	expr_ = new LinearExpr(c);
	node_type_ = LINEAR;
}

SymbolicExpr::SymbolicExpr(value_t c, var_t v) {
	expr_ = new LinearExpr(c,v);
	node_type_ = LINEAR;
}

SymbolicExpr::SymbolicExpr(const SymbolicExpr& e)
  : expr_(e.expr_), left_(e.left_), right_(e.right_), op_type_(e.op_type_), node_type_(e.node_type_), value_(e.value_) { }

SymbolicExpr::SymbolicExpr(SymbolicExpr *l, SymbolicExpr *r, op_type op,
		  node_type no, ops::binary_op_t binop, ops::unary_op_t unop,
		  LinearExpr *exp, value_t v)
	: left_(l), right_(r), op_type_(op), node_type_(no), binary_op_(binop), unary_op_(unop), expr_(exp), value_(v) {;}

size_t SymbolicExpr::Size() {
	if(node_type_ == LINEAR) return expr_->Size();
	else return 1 + left_->Size() + right_->Size();
}

value_t SymbolicExpr::const_term() {
	if(node_type_ == LINEAR) return expr_->const_term();
	return LONG_LONG_MIN;
}

const map<var_t,value_t>& SymbolicExpr::terms() {
	if(node_type_ == LINEAR) return expr_->terms();
	else {
		if(op_type_ == UNARY) {
			return left_->terms();
		}
		else {
			map<var_t, value_t> *m = new map<var_t, value_t>();
			return *m;
		}
	}
}

void SymbolicExpr::Negate() {
	if(node_type_ == LINEAR) expr_->Negate();
	else {
		SymbolicExpr *c = new SymbolicExpr(left_, right_, op_type_, node_type_, binary_op_, unary_op_, NULL, 0 - value_);
		right_ = NULL;
		node_type_ = NONLINEAR;
		op_type_ = UNARY;
		unary_op_ = ops::NEGATE;
		left_ = c;
	}
}

void SymbolicExpr::AppendVars(set<var_t>* vars) const {
  if(node_type_ == LINEAR)
	  expr_->AppendVars(vars);
}

bool SymbolicExpr::DependsOn(const map<var_t,type_t>& vars) const {
	if(node_type_ == LINEAR) {
		if(expr_->DependsOn(vars)) return true;
		return false;
	}
	else {
		return left_->DependsOn(vars) || right_->DependsOn(vars);
	}
}

void SymbolicExpr::AppendToString(string* s) const {

	char buff[32];
	if(node_type_ == LINEAR) expr_->AppendToString(s);
	else {
		if(op_type_ == UNARY){
			sprintf(buff, "(%d ", unary_op_);
			s->append(buff);
			left_->AppendToString(s);
		}
		else if(op_type_ == BINARY) {
			sprintf(buff, "(%d ", binary_op_);
			s->append(buff);
			left_->AppendToString(s);
			right_->AppendToString(s);
		}
		s->push_back(')');
	}
}


void SymbolicExpr::Serialize(string* s) const {
  if(node_type_ == LINEAR) expr_->Serialize(s);
  else {
	  if(op_type_ == UNARY){
		  s->push_back(static_cast<char>(unary_op_));
		  left_->Serialize(s);
	  }
	  else if(op_type_ == BINARY) {
		  s->push_back(static_cast<char>(binary_op_));
		  left_->Serialize(s);
		  right_->Serialize(s);
	  }
  }
}


bool SymbolicExpr::Parse(istream& s) {
	if(node_type_ == LINEAR) return expr_->Parse(s);
	else {
		if(op_type_ == UNARY) {

		}
		else if(op_type_ == BINARY) {

		}
	}
	return true;
}


const SymbolicExpr& SymbolicExpr::operator+=(SymbolicExpr& e) {
	if(node_type_ == LINEAR && e.node_type_ == LINEAR) {
		(*expr_) += (*e.expr_);
		value_ += e.getValue();
		return *this;
	}
	SymbolicExpr *c = new SymbolicExpr(this, &e, BINARY, NONLINEAR, ops::ADD, unary_op_, NULL, value_ + e.getValue());
	return *c;
}


const SymbolicExpr& SymbolicExpr::operator-=(SymbolicExpr& e) {
	if(node_type_ == LINEAR && e.node_type_ == LINEAR) {
			(*expr_) -= (*e.expr_);
			return *this;
		}
	SymbolicExpr *c = new SymbolicExpr(this, &e, BINARY, NONLINEAR, ops::SUBTRACT, unary_op_, NULL, value_ - e.getValue());
	return *c;
}

const SymbolicExpr& SymbolicExpr::operator+=(value_t c) {
	if(node_type_ == LINEAR) {
			expr_ += c;
			return *this;
		}
	SymbolicExpr *c1 = new SymbolicExpr(this, new SymbolicExpr(c), BINARY, NONLINEAR, ops::ADD, unary_op_, NULL, value_ + c);
	return *c1;
}


const SymbolicExpr& SymbolicExpr::operator-=(value_t c) {
	if(node_type_ == LINEAR) {
			expr_ -= c;
			return *this;
	}
	SymbolicExpr *c1 = new SymbolicExpr(this, new SymbolicExpr(c), BINARY, NONLINEAR, ops::SUBTRACT, unary_op_, NULL, value_ - c);
	return *c1;
}


const SymbolicExpr& SymbolicExpr::operator*=(value_t c) {
	if(node_type_ == LINEAR) {
			*expr_ *= c;
			return *this;
		}
	SymbolicExpr *c1 = new SymbolicExpr(this, new SymbolicExpr(c), BINARY, NONLINEAR, ops::MULTIPLY, unary_op_, NULL, value_ * c);
	return *c1;
}

bool SymbolicExpr::operator==(const SymbolicExpr& e) const {
	if(node_type_ == LINEAR && e.node_type_ == LINEAR) {
		return expr_ == e.expr_;
	}
	return (*left_ == *(e.left_)) && (*right_ == *(e.right_));
}

SymbolicExpr& SymbolicExpr::applyUnary(ops::unary_op_t op) {
	SymbolicExpr *c1 = new SymbolicExpr(this, NULL, UNARY, NONLINEAR, binary_op_, op, expr_, Apply(op, value_));
	return *c1;
}

SymbolicExpr& SymbolicExpr::applyBinary(SymbolicExpr &e, ops::binary_op_t op) {
	SymbolicExpr *c1 = new SymbolicExpr(this, &e, BINARY, NONLINEAR, op, unary_op_, expr_, Apply(op, value_, e.getValue()));
	return *c1;
}

SymbolicExpr& SymbolicExpr::applyDeref() {
	SymbolicExpr *c1 = new SymbolicExpr(left_, right_, BINARY, NONLINEAR, binary_op_, unary_op_, expr_, value_);
	left_ = c1;
	right_= NULL;
	op_type_ = DEREF;
	node_type_ = NONLINEAR;
	expr_ = NULL;
	value_ = (value_t)&value_;
	//TODO: Append the the symbolic writes

	return *this;
}

value_t SymbolicExpr::Apply(ops::binary_op_t bin_op, value_t v1, value_t v2) {
	switch(bin_op) {
	case ops::SHIFT_L: return v1<<v2;
	case ops::SHIFT_R: return v1>>v2;
	case ops::BITWISE_AND: return v1&v2;
	case ops::BITWISE_OR: return v1|v2;
	case ops::BITWISE_XOR: return v1^v2;
	default: {
		fprintf(stderr,"Unknown unary operator %d\n", bin_op);
		exit(1);
	}
	}
}

value_t SymbolicExpr::Apply(ops::unary_op_t un_op, value_t v) {
	switch(un_op) {
	case ops::NEGATE: return 0 - v;
	case ops::BITWISE_NOT: return ~v;
	case ops::LOGICAL_NOT: return !v;
	default: {
		fprintf(stderr, "Unknown unary operator %d\n", un_op);
		exit(1);
	}
	}
}
}  // namespace crest
