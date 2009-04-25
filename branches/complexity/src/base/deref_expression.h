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
 * Author: Sudeep Juvekar (sjuvekar@eecs.berkeley.edu)
 */

#ifndef DEREF_EXPRESSION_H_
#define DEREF_EXPRESSION_H_

#include <istream>
#include <map>
#include <vector>
#include <ostream>
#include <set>
#include <string>
#include <yices_c.h>
#include<ext/hash_map>

#include "base/basic_types.h"
#include "base/symbolic_expression.h"
#include "base/symbolic_object.h"

using std::istream;
using std::map;
using std::ostream;
using std::set;
using std::string;
using std::vector;

namespace crest {
/***
 * Dereference Expression
 */

class DerefExpr : public SymbolicExpr {
private:
	 const SymbolicObject *object_; // The symbolic object corresponding to the dereference
	 SymbolicExpr *symbolic_addr_; //A symbolic expression representing the symbolic address of this deref
	 unsigned char* concrete_bytes_;

public:
	 DerefExpr(SymbolicExpr *c, SymbolicObject *o, size_t , value_t v);
	 ~DerefExpr();
	 size_t Size();
	 void AppendVars(set<var_t>* vars);
	 bool DependsOn(const map<var_t,type_t>& vars);
	 void AppendToString(string *s);
	 bool IsConcrete();
	 bool operator==(DerefExpr &e);
	 void bit_blast(yices_expr &e, yices_context &ctx, map<var_t, yices_var_decl> &x_decl);
};

}
#endif /* DEREF_EXPRESSION_H_ */
