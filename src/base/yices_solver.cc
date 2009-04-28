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
 * Author: Jacob Burnim (jburnim@cs.berkeley.edu)
 * 		   Sudeep Juvekar (sjuvekar@eecs.berkeley.edu)
 */
#include <assert.h>
#include <queue>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <utility>
#include <yices_c.h>

#include "base/yices_solver.h"
#include "base/symbolic_expression.h"

using std::make_pair;
using std::queue;
using std::set;

namespace crest {

typedef vector<const SymbolicExpr*>::const_iterator PredIt;


bool YicesSolver::IncrementalSolve(const vector<value_t>& old_soln,
				   const map<var_t,type_t>& vars,
				   const vector<const SymbolicExpr*>& constraints,
				   map<var_t,value_t>* soln) {
  set<var_t> tmp;
  typedef set<var_t>::const_iterator VarIt;

  // Build a graph on the variables, indicating a dependence when two
  // variables co-occur in a symbolic predicate.
  vector< set<var_t> > depends(vars.size());
  for (PredIt i = constraints.begin(); i != constraints.end(); ++i) {
    tmp.clear();
    (*i)->AppendVars(&tmp);
    for (VarIt j = tmp.begin(); j != tmp.end(); ++j) {
      depends[*j].insert(tmp.begin(), tmp.end());
    }
  }

  // Initialize the set of dependent variables to those in the constraints.
  // (Assumption: Last element of constraints is the only new constraint.)
  // Also, initialize the queue for the BFS.
  map<var_t,type_t> dependent_vars;
  queue<var_t> Q;
  tmp.clear();
  constraints.back()->AppendVars(&tmp);
  for (VarIt j = tmp.begin(); j != tmp.end(); ++j) {
    dependent_vars.insert(*vars.find(*j));
    Q.push(*j);
  }

  // Run the BFS.
  while (!Q.empty()) {
    var_t i = Q.front();
    Q.pop();
    for (VarIt j = depends[i].begin(); j != depends[i].end(); ++j) {
      if (dependent_vars.find(*j) == dependent_vars.end()) {
	Q.push(*j);
	dependent_vars.insert(*vars.find(*j));
      }
    }
  }

  // Generate the list of dependent constraints.
  vector<const SymbolicExpr*> dependent_constraints;
  for (PredIt i = constraints.begin(); i != constraints.end(); ++i) {
    if ((*i)->DependsOn(dependent_vars))
      dependent_constraints.push_back(*i);
  }

  soln->clear();
  if (Solve(dependent_vars, dependent_constraints, soln)) {
    // Merge in the constrained variables.
    for (PredIt i = constraints.begin(); i != constraints.end(); ++i) {
      (*i)->AppendVars(&tmp);
    }
    for (set<var_t>::const_iterator i = tmp.begin(); i != tmp.end(); ++i) {
      if (soln->find(*i) == soln->end()) {
	soln->insert(make_pair(*i, old_soln[*i]));
      }
    }
    return true;
  }

  return false;
}


bool YicesSolver::Solve(const map<var_t,type_t>& vars,
			const vector<const SymbolicExpr*>& constraints,
			map<var_t,value_t>* soln) {

  typedef map<var_t,type_t>::const_iterator VarIt;
  yices_context ctx = yices_mk_context();
  assert(ctx);

  yices_expr zero = yices_mk_num(ctx, 0);
  assert(zero);

  // Variable declarations.
  map<var_t,yices_var_decl> x_decl;
  for (VarIt i = vars.begin(); i != vars.end(); ++i) {
    char name[24];
    sprintf(name, "x%u", i->first);

    size_t size = 8 * kSizeOfType[i->second];
    yices_type ty = yices_mk_bitvector_type(ctx, size);

    yices_var_decl decl = yices_mk_var_decl(ctx, name, ty);
    assert(decl);
    x_decl[i->first] = decl;
  }

  // Assertions.
  for (PredIt i = constraints.begin(); i != constraints.end(); ++i) {
    const SymbolicExpr& se = **i; //(*i)->expr();

    // TODO: Have to decide whether we're using SymbolicPred's or
    // CompareExpr's here and in the symbolic interpreter, symbolic path,
    // symbolic execution, etc.
    //
    // Currently maintained as CompareExprs

    yices_expr e = se.BitBlast(ctx);

    /*
    yices_expr pred;
    switch((*i)->op()) {
    case ops::EQ:    pred = yices_mk_eq(ctx, e, zero); break;
    case ops::NEQ:   pred = yices_mk_diseq(ctx, e, zero); break;
    case ops::GT:    pred = yices_mk_gt(ctx, e, zero); break;
    case ops::LE:    pred = yices_mk_le(ctx, e, zero); break;
    case ops::LT:    pred = yices_mk_lt(ctx, e, zero); break;
    case ops::GE:    pred = yices_mk_ge(ctx, e, zero); break;
    case ops::S_GT:  pred = yices_mk_gt(ctx, e, zero); break;
    case ops::S_LE:  pred = yices_mk_le(ctx, e, zero); break;
    case ops::S_LT:  pred = yices_mk_lt(ctx, e, zero); break;
    case ops::S_GE:  pred = yices_mk_ge(ctx, e, zero); break;
    default:
      fprintf(stderr, "Unknown comparison operator: %d\n", (*i)->op());
      exit(1);
    }
    yices_assert(ctx, pred);
    */
    yices_assert(ctx, e);
  }


  //CHANGE: With symbolic expression, simply assert it!

  bool success = (yices_check(ctx) == l_true);
  if (success) {
    soln->clear();
    yices_model model = yices_get_model(ctx);
    for (VarIt i = vars.begin(); i != vars.end(); ++i) {
      long val;

      assert(yices_get_int_value(model, x_decl[i->first], &val));
      soln->insert(make_pair(i->first, val));
    }
  }

  yices_del_context(ctx);
  return success;
}




}  // namespace crest

