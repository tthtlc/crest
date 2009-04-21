(* Copyright (c) 2008, Jacob Burnim (jburnim@cs.berkeley.edu)
 *
 * This file is part of CREST, which is distributed under the revised
 * BSD license.  A copy of this license can be found in the file LICENSE.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See LICENSE
 * for details.
 *)

open Cil
open Formatcil

(*
 * Utilities that should be in the O'Caml standard libraries.
 *)

let isSome o =
  match o with
    | Some _ -> true
    | None   -> false

let rec mapOptional f ls =
  match ls with
    | [] -> []
    | (x::xs) -> (match (f x) with
                    | None -> mapOptional f xs
                    | Some x' -> x' :: mapOptional f xs)

let concatMap f ls =
  let rec doIt res ls =
    match ls with
      | [] -> List.rev res
      | (x::xs) -> doIt (List.rev_append (f x) res) xs
  in
    doIt [] ls

let open_append fname =
  open_out_gen [Open_append; Open_creat; Open_text] 0o700 fname


(*
 * We maintain several bits of state while instrumenting a program:
 *  - the last id assigned to an instrumentation call
 *    (equal to the number of such inserted calls)
 *  - the last id assigned to a statement in the program
 *    (equal to the number of CFG-transformed statements)
 *  - the last id assigned to a function
 *  - the set of all branches seen so far (stored as pairs of branch
 *    id's -- with paired true and false branches stored together),
 *    annotating branches with the funcion they are in
 *  - a per-function control-flow graph (CFG), along with all calls
 *    between functions
 *  - a map from function names to the first statement ID in the function
 *    (to build the complete CFG once all files have been processed)
 *
 * Because the CIL executable will be run once per source file in the
 * instrumented program, we must save/restore this state in files
 * between CIL executions.  (These last two bits of state are
 * write-only -- at the end of each run we just append updates.)
 *)

let idCount = ref 0
let stmtCount = Cfg.start_id
let funCount = ref 0
let branches = ref []
let curBranches = ref []
(* Control-flow graph is stored inside the CIL AST. *)

let getNewId () = ((idCount := !idCount + 1); !idCount)
let addBranchPair bp = (curBranches := bp :: !curBranches)
let addFunction () = (branches := (!funCount, !curBranches) :: !branches;
		      curBranches := [];
		      funCount := !funCount + 1)

let readCounter fname =
  try
    let f = open_in fname in
      Scanf.fscanf f "%d" (fun x -> x)
  with x -> 0

let writeCounter fname (cnt : int) =
  try
    let f = open_out fname in
      Printf.fprintf f "%d\n" cnt ;
      close_out f
  with x ->
    failwith ("Failed to write counter to: " ^ fname ^ "\n")

let readIdCount () = (idCount := readCounter "idcount")
let readStmtCount () = (stmtCount := readCounter "stmtcount")
let readFunCount () = (funCount := readCounter "funcount")

let writeIdCount () = writeCounter "idcount" !idCount
let writeStmtCount () = writeCounter "stmtcount" !stmtCount
let writeFunCount () = writeCounter "funcount" !funCount

let writeBranches () =
  let writeFunBranches out (fid, bs) =
    if (fid > 0) then
      (let sorted = List.sort compare bs in
         Printf.fprintf out "%d %d\n" fid (List.length bs) ;
         List.iter (fun (s,d) -> Printf.fprintf out "%d %d\n" s d) sorted)
  in
    try
      let f = open_append "branches" in
      let allBranches = (!funCount, !curBranches) :: !branches in
        List.iter (writeFunBranches f) (List.tl (List.rev allBranches));
        close_out f
    with x ->
      prerr_string "Failed to write branches.\n"

(* Visitor which walks the CIL AST, printing the (already computed) CFG. *)
class writeCfgVisitor out firstStmtIdMap =
object (self)
  inherit nopCilVisitor
  val out = out
  val firstStmtIdMap = firstStmtIdMap

  method writeCfgCall f =
    if List.mem_assq f firstStmtIdMap then
      Printf.fprintf out " %d" (List.assq f firstStmtIdMap).sid
    else
      Printf.fprintf out " %s" f.vname

  method writeCfgInst i =
     match i with
         Call(_, Lval(Var f, _), _, _) -> self#writeCfgCall f
       | _ -> ()

  method vstmt(s) =
    Printf.fprintf out "%d" s.sid ;
    List.iter (fun dst -> Printf.fprintf out " %d" dst.sid) s.succs ;
    (match s.skind with
         Instr is -> List.iter self#writeCfgInst is
       | _       -> ()) ;
    output_string out "\n" ;
    DoChildren

end

let writeCfg cilFile firstStmtIdMap =
  try
    let out = open_append "cfg" in
    let wcfgv = new writeCfgVisitor out firstStmtIdMap in
    visitCilFileSameGlobals (wcfgv :> cilVisitor) cilFile ;
    close_out out
  with x ->
    prerr_string "Failed to write CFG.\n"

let buildFirstStmtIdMap cilFile =
  let getFirstFuncStmtId glob =
    match glob with
      | GFun(f, _) -> Some (f.svar, List.hd f.sbody.bstmts)
      | _ -> None
  in
    mapOptional getFirstFuncStmtId cilFile.globals

let writeFirstStmtIdMap firstStmtIdMap =
  let writeEntry out (f,s) =
    (* To help avoid "collisions", skip static functions. *)
    if not (f.vstorage = Static) then
      Printf.fprintf out "%s %d\n" f.vname s.sid
  in
  try
    let out = open_append "cfg_func_map" in
    List.iter (writeEntry out) firstStmtIdMap ;
    close_out out
  with x ->
    prerr_string "Failed to write (function, first statement ID) map.\n"

let handleCallEdgesAndWriteCfg cilFile =
  let stmtMap = buildFirstStmtIdMap cilFile in
   writeCfg cilFile stmtMap ;
   writeFirstStmtIdMap stmtMap


(* Utilities *)

let noAddr = zero

let shouldSkipFunction f = hasAttribute "crest_skip" f.vattr

let prependToBlock (is : instr list) (b : block) =
  b.bstmts <- mkStmt (Instr is) :: b.bstmts

(* Should we instrument sub-expressions of a given type? *)
let isSymbolicType ty =
  match (unrollType ty) with
   | TInt _ | TPtr _ | TEnum _ -> true
   | _ -> false

(* These definitions must match those in "libcrest/crest.h". *)
let idType   = intType
let bidType  = intType
let fidType  = uintType
let valType  = TInt (ILongLong, [])
let addrType = TInt (IULong, [])
let boolType = TInt (IUChar, [])
let opType   = intType  (* enum *)
let typeType = intType  (* enum *)

(*
 * normalizeConditionalsVisitor ensures that every if block has an
 * accompanying else block (by adding empty "else { }" blocks where
 * necessary).  It also attempts to convert conditional expressions
 * into predicates (i.e. binary expressions with one of the comparison
 * operators ==, !=, >, <, >=, <=.)
 *)
class normalizeConditionalsVisitor =

  let isCompareOp op =
    match op with
      | Eq -> true  | Ne -> true  | Lt -> true
      | Gt -> true  | Le -> true  | Ge -> true
      | _ -> false
  in

  let negateCompareOp op =
    match op with
      | Eq -> Ne  | Ne -> Eq
      | Lt -> Ge  | Ge -> Lt
      | Le -> Gt  | Gt -> Le
      | _ ->
          invalid_arg "negateCompareOp"
  in

  (* TODO(jburnim): We ignore casts here because downcasting can
   * convert a non-zero value into a zero -- e.g. from a larger to a
   * smaller integral type.  However, we could safely handle casting
   * from smaller to larger integral types. *)
  let rec mkPredicate e negated =
    match e with
      | UnOp (LNot, e, _) -> mkPredicate e (not negated)

      | BinOp (op, e1, e2, ty) when isCompareOp op ->
          if negated then
            BinOp (negateCompareOp op, e1, e2, ty)
          else
            e

      | _ ->
          let op = if negated then Eq else Ne in
            BinOp (op, e, zero, intType)
  in

object (self)
  inherit nopCilVisitor

  method vstmt(s) =
    match s.skind with
      | If (e, b1, b2, loc) ->
          (* Ensure neither branch is empty. *)
          if (b1.bstmts == []) then b1.bstmts <- [mkEmptyStmt ()] ;
          if (b2.bstmts == []) then b2.bstmts <- [mkEmptyStmt ()] ;
          (* Ensure the conditional is actually a predicate. *)
          s.skind <- If (mkPredicate e false, b1, b2, loc) ;
          DoChildren

      | _ -> DoChildren

end


let addressOf : lval -> exp = mkAddrOrStartOf


let hasAddress (_, off) =
  let rec containsBitField off =
    match off with
      | NoOffset         -> false
      | Field (fi, off) -> (isSome fi.fbitfield) || (containsBitField off)
      | Index (_, off)  -> containsBitField off
  in
    not (containsBitField off)

let idArg   = ("id",   idType,        [])
let bidArg  = ("bid",  bidType,       [])
let fidArg  = ("fid",  fidType,       [])
let valArg  = ("val",  valType,       [])
let addrArg = ("addr", addrType,      [])
let opArg   = ("op",   opType,        [])
let boolArg = ("b",    boolType,      [])
let typeArg = ("type", typeType,      [])
let sizeArg () = ("size", !typeOfSizeOf, [])

let mkInstFunc f name args =
  let ty = TFun (voidType, Some (idArg :: args), false, []) in
  let func = findOrCreateFunc f ("__Crest" ^ name) ty in
    func.vstorage <- Extern ;
    func.vattr <- [Attr ("crest_skip", [])] ;
    func

let mkInstCall func args =
  let args' = integer (getNewId ()) :: args in
    Call (None, Lval (var func), args', locUnknown)

let toAddr e = CastE (addrType, e)


class crestInstrumentVisitor f =
  (*
   * Get handles to the instrumentation functions.
   *
   * NOTE: If the file we are instrumenting includes "crest.h", this
   * code will grab the varinfo's from the included declarations.
   * Otherwise, it will create declarations for these functions.
   *)
  let loadFunc         = mkInstFunc f "Load" [addrArg; typeArg; valArg] in
  let loadAggrFunc     = mkInstFunc f "LoadAggr" [addrArg; typeArg; sizeArg ()] in
  let derefFunc        = mkInstFunc f "Deref" [addrArg; typeArg; valArg] in
  let storeFunc        = mkInstFunc f "Store" [addrArg] in
  let writeFunc        = mkInstFunc f "Write" [addrArg] in
  let clearStackFunc   = mkInstFunc f "ClearStack" [] in
  let apply1Func       = mkInstFunc f "Apply1" [opArg; typeArg; valArg] in
  let apply2Func       = mkInstFunc f "Apply2" [opArg; typeArg; valArg] in
  let ptrApply2Func    = mkInstFunc f "PtrApply2" [opArg; sizeArg (); valArg] in
  let branchFunc       = mkInstFunc f "Branch" [bidArg; boolArg] in
  let callFunc         = mkInstFunc f "Call" [fidArg] in
  let returnFunc       = mkInstFunc f "Return" [] in
  let handleReturnFunc = mkInstFunc f "HandleReturn" [typeArg; valArg] in

  (*
   * Functions to create calls to the above instrumentation functions.
   *)
  let unaryOpCode op =
    let c =
      match op with
        | Neg -> 19  | BNot -> 20  |  LNot -> 21
    in
      integer c
  in

  let castOp = integer 22 in

  let binaryOpCode op =
    let c =
      match op with
        | PlusA   ->  0  | MinusA  ->  1  | Mult  ->  2  | Div   ->  3
        | Mod     ->  4  | BAnd    ->  5  | BOr   ->  6  | BXor  ->  7
        | Shiftlt ->  8  | Shiftrt ->  9  | LAnd  -> 10  | LOr   -> 11
        | Eq      -> 12  | Ne      -> 13  | Gt    -> 14  | Le    -> 15
        | Lt      -> 16  | Ge      -> 17
            (* Other/unhandled operators discarded and treated concretely. *)
            (* Have to handle "pointer - pointer" and "pointer +/- int". *)
        | _ -> 18
    in
      integer c
  in

  let isPointerOp op =
    match op with
      | PlusPI | IndexPI | MinusPI | MinusPP -> true
      | _ -> false
  in

  let toValue e =
      if isPointerType (typeOf e) then
        CastE (valType, CastE (addrType, e))
      else
        CastE (valType, e)
  in

  let toType ty =
    let tyCode =
      match (unrollType ty) with
        | TInt (IUChar,     _) ->  0
        | TInt (ISChar,     _) ->  1
        | TInt (IChar,      _) ->  1   (* we assume 'char' is signed *)
        | TInt (IUShort,    _) ->  2
        | TInt (IShort,     _) ->  3
        | TInt (IUInt,      _) ->  4
        | TInt (IInt,       _) ->  5
        | TInt (IULong,     _) ->  6
        | TInt (ILong,      _) ->  7
        | TInt (IULongLong, _) ->  8
        | TInt (ILongLong,  _) ->  9
        (* TODO(jburnim): Is unsigned long correct for pointers? *)
        | TPtr _               ->  6
        (* TODO(jburnim): Is int32 correct for enums? *)
        | TEnum _              ->  5
        (* Arrays, structures, and unions are "aggregates". *)
        | TArray _             -> 10
        | TComp _              -> 10
        | _ -> invalid_arg "toType"
    in
      integer tyCode
  in

  let loadVal ty v =
    if isSymbolicType ty then
      toValue v
    else
      sizeOf ty
  in

  let mkLoad addr ty v    = mkInstCall loadFunc [toAddr addr; toType ty; loadVal ty v] in
  let mkDeref addr ty v   = mkInstCall derefFunc [toAddr addr; toType ty; loadVal ty v] in
  let mkStore addr        = mkInstCall storeFunc [toAddr addr] in
  let mkWrite addr        = mkInstCall writeFunc [toAddr addr] in
  let mkClearStack ()     = mkInstCall clearStackFunc [] in
  let mkCast ty v         = mkInstCall apply1Func [castOp; toType ty; toValue v] in
  let mkApply1 op ty v    = mkInstCall apply1Func [unaryOpCode op; toType ty; toValue v] in
  let mkApply2 op ty v    = mkInstCall apply2Func [binaryOpCode op; toType ty; toValue v] in
  let mkPtrApply2 op sz v = mkInstCall ptrApply2Func [binaryOpCode op; sz; toValue v] in
  let mkBranch bid b      = mkInstCall branchFunc [integer bid; integer b] in
  let mkCall fid          = mkInstCall callFunc [integer fid] in
  let mkReturn ()         = mkInstCall returnFunc [] in
  let mkHandleReturn ty v = mkInstCall handleReturnFunc [toType ty; loadVal ty v] in


  (*
   * Could the given lvalue have a symbolic address?
   *)
  let isSymbolicLvalue lv =
    let rec isSymbolicOffset off =
      match off with
        | NoOffset         -> false
        | Index (e, off')  -> true   (* NOTE: Could skip constant offsets. *)
        | Field (_, off')  -> isSymbolicOffset off'
    in
      match lv with
        | (Mem m, off) -> true
        | (Var v, off) -> isSymbolicOffset off
  in

  (*
   * Return the expression for the concrete value to load in a load or deref
   * instruction.  For lvalues of primitive type, this is the actual concrete
   * value.  But for structs or enums, this is the *size* of the lvalue.
   *)
  let loadValue lv =
    let ty = typeOfLval lv in
      match ty with
        | TComp _ -> sizeOf ty
        | _ ->       Lval lv
  in

  (*
   * Instrument an lvalue.
   *
   * Generates instrumentation which puts the lvalue's address on the stack.
   *)
  let rec instrumentLvalueAddr lv =
    let lv', off = removeOffsetLval lv in
      match off with
        | NoOffset     ->
            ((* Load address of the lvalue's host. *)
             match lv with
               | (Var v, _) -> [mkLoad noAddr (typeOf (addressOf lv)) (addressOf lv)]
               | (Mem e, _) -> instrumentExpr e)
        | Index (e, _) ->
            (instrumentLvalueAddr lv')
            @ (instrumentExpr e)
            @ [mkPtrApply2 IndexPI (sizeOf (typeOfLval lv)) (addressOf lv)]
(*
            @ [mkLoad noAddr addrType (sizeOf (typeOf lv')) ;
               mkApply2 Mult addrType zero ;
               mkApply2 PlusA addrType (addressOf lv)]
 *)
        | Field (f, _) ->
            let fieldOff = cExp "&%l:lv1 - &%l:lv2" [("lv1", Fl lv); ("lv2", Fl lv')] in
              (instrumentLvalueAddr lv')
              @ [mkLoad noAddr !typeOfSizeOf fieldOff ;
                 mkPtrApply2 IndexPI one (addressOf lv)]

  (*
   * Instrument an expression.
   *)
  and instrumentExpr e =
    let ty = typeOf e in
    if isConstant e then
      [mkLoad noAddr ty e]
    else
      match e with
        | Lval lv when hasAddress lv ->
            (* If reading the lvalue might involve a dereference of a
             * symbolic pointer, then instrument the lvalue's address
             * and do a dereference. Otherwise, just do a load. *)
            if (isSymbolicLvalue lv) then
              (instrumentLvalueAddr lv)
              @ [mkDeref (addressOf lv) ty e]
            else
              [mkLoad (addressOf lv) ty e]

        | UnOp (op, e', _) ->
            (* Should skip this if we don't currently handle 'op'? *)
            (instrumentExpr e') @ [mkApply1 op ty e]

        | BinOp (op, e1, e2, _) when isPointerOp op ->
            let TPtr (baseTy, _) = unrollType (typeOf e1) in
              (instrumentExpr e1) @ (instrumentExpr e2)
              @ [mkPtrApply2 op (sizeOf baseTy) e]

(*
        | BinOp (MinusPP, e1, e2, _) ->
            let TPtr (baseTy, _) = unrollType (typeOf e1) in
            let diff = cExp "(%e:e1-%e:e2)*sizeof(%t:t)"
                            [("e1", e1), ("e2", e2), ("t", baseTy)] in
              (instrumentExpr e1) @ (instrumentExpr e2)
              @ [mkApply2 MinusA addrType diff ;
                 mkLoad noAddr addrType sizeOf(baseTy) ;
                 mkApply2 Div addrType e]
 *)

        | BinOp (op, e1, e2, _) ->
            (* Should skip this if we don't currently handle 'op'? *)
            (instrumentExpr e1) @ (instrumentExpr e2) @ [mkApply2 op ty e]

        | CastE (_, e') ->
            (instrumentExpr e') @ [mkCast ty e]

        | AddrOf lv ->
            instrumentLvalueAddr lv

        | StartOf lv ->
            instrumentLvalueAddr lv

        (* Default case: sizeof() and __alignof__() expressions. *)
        | _ -> [mkLoad noAddr ty e]
  in

object (self)
  inherit nopCilVisitor

  (*
   * Instrument a statement (branch or function return).
   *)
  method vstmt(s) =
    match s.skind with
      | If (e, b1, b2, _) ->
          let getFirstStmtId blk = (List.hd blk.bstmts).sid in
          let b1_sid = getFirstStmtId b1 in
          let b2_sid = getFirstStmtId b2 in
	    (self#queueInstr (instrumentExpr e) ;
	     prependToBlock [mkBranch b1_sid 1] b1 ;
	     prependToBlock [mkBranch b2_sid 0] b2 ;
             addBranchPair (b1_sid, b2_sid)) ;
            DoChildren

      | Return (Some e, _) ->
          if isSymbolicType (typeOf e) then
            self#queueInstr (instrumentExpr e) ;
          self#queueInstr [mkReturn ()] ;
          SkipChildren

      | Return (None, _) ->
          self#queueInstr [mkReturn ()] ;
          SkipChildren

      | _ -> DoChildren

  (*
   * Instrument assignment and call statements.
   *)
  method vinst(i) =
    match i with
      | Set (lv, e, _) when (true && hasAddress lv) (*type is ok, lv has addr *) ->
          if (isSymbolicLvalue lv) then
            (self#queueInstr (instrumentLvalueAddr lv) ;
             self#queueInstr (instrumentExpr e) ;
             self#queueInstr [mkWrite (addressOf lv)] ;
             SkipChildren)
          else
            (* If lv is an aggregate, it must be a struct/union. *)
            (self#queueInstr (instrumentExpr e) ;
             self#queueInstr [mkStore (addressOf lv)] ;
             SkipChildren)

      (* Don't instrument calls to functions marked as uninstrumented. *)
      | Call (_, Lval (Var f, NoOffset), _, _)
          when shouldSkipFunction f -> SkipChildren

      | Call (ret, _, args, _) ->
          let isSymbolicExp e = isSymbolicType (typeOf e) in
          let isSymbolicLval lv = isSymbolicType (typeOfLval lv) in
          let argsToInst = List.filter isSymbolicExp args in
            self#queueInstr (concatMap instrumentExpr argsToInst) ;
            (match ret with
               | Some lv when ((isSymbolicLval lv) && (hasAddress lv)) ->
                   ChangeTo [i ;
                             mkHandleReturn (typeOfLval lv) (Lval lv) ;
                             mkStore (addressOf lv)]
               | _ ->
                   ChangeTo [i ; mkClearStack ()])

      | _ -> DoChildren


  (*
   * Instrument function entry.
   *)
  method vfunc(f) =
    if shouldSkipFunction f.svar then
      SkipChildren
    else
      let instParam v = mkStore (addressOf (var v)) in
      let isSymbolic v = isSymbolicType v.vtype in
      let (_, _, isVarArgs, _) = splitFunctionType f.svar.vtype in
      let paramsToInst = List.filter isSymbolic f.sformals in
        addFunction () ;
        if (not isVarArgs) then
          prependToBlock (List.rev_map instParam paramsToInst) f.sbody ;
        prependToBlock [mkCall !funCount] f.sbody ;
        DoChildren

end

let registerGlobals f =
  let regGlobalFunc = mkInstFunc f "RegGlobal" [addrArg; sizeArg ()] in
  let mkRegGlobal addr sz = mkInstCall regGlobalFunc [toAddr addr; sz] in
  let isIndexableType ty =
    match ty with
      | TArray _ | TComp _ -> isCompleteType ty
      | _ -> false
  in
  let registerGlobal glob =
    match glob with
      | GVarDecl (v, _) when (v.vstorage == Extern) && isIndexableType v.vtype ->
          Some (mkRegGlobal (addressOf (var v)) (sizeOf v.vtype))
      | GVar (v, _, _) when isIndexableType v.vtype ->
          Some (mkRegGlobal (addressOf (var v)) (sizeOf v.vtype))
      | _ -> None
  in
    mapOptional registerGlobal f.globals

let addCrestInitializer f =
  let crestInitFunc = mkInstFunc f "Init" [] in
  let globalInit = getGlobInit f in
    crestInitFunc.vstorage <- Extern ;
    crestInitFunc.vattr <- [Attr ("crest_skip", [])] ;
    prependToBlock (registerGlobals f) globalInit.sbody ;
    prependToBlock [mkInstCall crestInitFunc []] globalInit.sbody

let prepareGlobalForCFG glob =
  match glob with
    | GFun(func, _) -> prepareCFG func
    | _ -> ()

let feature : featureDescr =
  { fd_name = "CrestInstrument";
    fd_enabled = ref false;
    fd_description = "instrument a program for use with CREST";
    fd_extraopt = [];
    fd_post_check = true;
    fd_doit =
      function (f: file) ->
        ((* Simplify the code:
          *  - simplifying expressions with complex memory references
          *  - converting loops and switches into goto's and if's
          *  - transforming functions to have exactly one return *)
          Simplemem.feature.fd_doit f ;
          iterGlobals f prepareGlobalForCFG ;
          Oneret.feature.fd_doit f ;
          (* To simplify later processing:
           *  - ensure that every 'if' has a non-empty else block
           *  - try to transform conditional expressions into predicates
           *    (e.g. "if (!x) {}" to "if (x == 0) {}") *)
          (let ncVisitor = new normalizeConditionalsVisitor in
             visitCilFileSameGlobals (ncVisitor :> cilVisitor) f) ;
          (* Clear out any existing CFG information. *)
          Cfg.clearFileCFG f ;
          (* Read the ID and statement counts from files.  (This must
           * occur after clearFileCFG, because clearFileCfg clobbers
           * the statement counter.) *)
          readIdCount () ;
          readStmtCount () ;
          readFunCount () ;
          (* Compute the control-flow graph. *)
          Cfg.computeFileCFG f ;
          (* Adds function calls to the CFG, by building a map from
           * function names to the first statements in those functions
           * and by explicitly adding edges for calls to functions
           * defined in this file. *)
          handleCallEdgesAndWriteCfg f ;
          (* Finally instrument the program. *)
	  (let instVisitor = new crestInstrumentVisitor f in
             visitCilFileSameGlobals (instVisitor :> cilVisitor) f) ;
          (* Add a function to initialize the instrumentation library. *)
          addCrestInitializer f ;
          (* Write the ID and statement counts, the branches. *)
          writeIdCount () ;
          writeStmtCount () ;
          writeFunCount () ;
          writeBranches ());
  }
