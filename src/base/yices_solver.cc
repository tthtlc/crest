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

typedef vector<const SymbolicPred*>::const_iterator PredIt;


bool YicesSolver::IncrementalSolve(const vector<value_t>& old_soln,
				   const map<var_t,type_t>& vars,
				   const vector<const SymbolicPred*>& constraints,
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
  vector<const SymbolicPred*> dependent_constraints;
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
			const vector<const SymbolicPred*>& constraints,
			map<var_t,value_t>* soln) {

  typedef map<var_t,type_t>::const_iterator VarIt;
  yices_context ctx = yices_mk_context();
  assert(ctx);

  yices_expr zero = yices_mk_num(ctx, 0);
  assert(zero);

  // Variable declarations.
  map<var_t,yices_var_decl> x_decl;


  for (PredIt i = constraints.begin(); i != constraints.end(); ++i) {
      SymbolicExpr& se = (SymbolicExpr&)(*i)->expr();

      yices_expr *e=NULL;
      se.bit_blast(*e, ctx, x_decl);

      yices_expr pred;
      switch((*i)->op()) {
      case ops::EQ:  pred = yices_mk_eq(ctx, *e, zero); break;
      case ops::NEQ: pred = yices_mk_diseq(ctx, *e, zero); break;
      case ops::GT:  pred = yices_mk_gt(ctx, *e, zero); break;
      case ops::LE:  pred = yices_mk_le(ctx, *e, zero); break;
      case ops::LT:  pred = yices_mk_lt(ctx, *e, zero); break;
      case ops::GE:  pred = yices_mk_ge(ctx, *e, zero); break;
      default:
    	  fprintf(stderr, "Unknown comparison operator: %d\n", (*i)->op());
    	  exit(1);
      }
      yices_assert(ctx, pred);
      delete e;
  }

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

