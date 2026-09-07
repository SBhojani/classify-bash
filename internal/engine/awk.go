package engine

import (
	"github.com/benhoyt/goawk/ast"
	"github.com/benhoyt/goawk/lexer"
	"github.com/benhoyt/goawk/parser"
)

// classifyAwkProgram parses src as an awk program and returns true only when
// every node is on the strict whitelist below. Same philosophy as the bash
// classifier: positively enumerate every safe construct, fall through on
// anything unfamiliar, and failLoud when a goawk release introduces a node
// kind the walker doesn't know about (so we extend the classifier rather
// than silently auto-allow new awk syntax).
//
// Rejections (return false):
//   - Parse error.
//   - Any user-defined function definition.
//   - print / printf with any redirect (`>`, `>>`, `|`).
//   - getline from a pipe (`cmd | getline`) or from a file (`getline < file`).
//   - CallExpr whose builtin is not on the allowlist (notably: system, getline,
//     close, fflush all rejected).
//   - UserCallExpr (defense-in-depth — user functions already rejected upfront).
//
// Verified against all of the above on 2026-07-27 (see DESIGN.md "Flag values
// that are programs" for the sweep this was part of): system(), print|"cmd",
// "cmd"|getline, getline<file, print>file and close/fflush all fall through.
//
// ENVIRON IS readable (`awk 'BEGIN{for(k in ENVIRON) print k"="ENVIRON[k]}'`
// classifies allow) and that is deliberate, not an oversight: bare `env` and
// `printenv` are already whitelisted and dump the environment more directly, so
// rejecting it here would buy nothing. If the environment ever stops being
// readable at Tier A, revisit this too.
func classifyAwkProgram(src string) bool {
	prog, err := parser.ParseProgram([]byte(src), nil)
	if err != nil {
		return false
	}
	if len(prog.Functions) > 0 {
		return false
	}
	for _, ss := range prog.Begin {
		if !walkAwkStmts(ss) {
			return false
		}
	}
	for _, action := range prog.Actions {
		for _, p := range action.Pattern {
			if !walkAwkExpr(p) {
				return false
			}
		}
		if !walkAwkStmts(action.Stmts) {
			return false
		}
	}
	for _, ss := range prog.End {
		if !walkAwkStmts(ss) {
			return false
		}
	}
	return true
}

func walkAwkStmts(ss ast.Stmts) bool {
	for _, s := range ss {
		if !walkAwkStmt(s) {
			return false
		}
	}
	return true
}

func walkAwkStmt(s ast.Stmt) bool {
	switch n := s.(type) {
	case *ast.PrintStmt:
		if n.Dest != nil {
			return false
		}
		return walkAwkExprs(n.Args)
	case *ast.PrintfStmt:
		if n.Dest != nil {
			return false
		}
		return walkAwkExprs(n.Args)
	case *ast.ExprStmt:
		return walkAwkExpr(n.Expr)
	case *ast.IfStmt:
		return walkAwkExpr(n.Cond) && walkAwkStmts(n.Body) && walkAwkStmts(n.Else)
	case *ast.ForStmt:
		return walkAwkOptStmt(n.Pre) && walkAwkOptExpr(n.Cond) &&
			walkAwkOptStmt(n.Post) && walkAwkStmts(n.Body)
	case *ast.ForInStmt:
		// Var and Array are strings (variable names); only the body has exprs.
		return walkAwkStmts(n.Body)
	case *ast.WhileStmt:
		return walkAwkExpr(n.Cond) && walkAwkStmts(n.Body)
	case *ast.DoWhileStmt:
		return walkAwkStmts(n.Body) && walkAwkExpr(n.Cond)
	case *ast.BreakStmt, *ast.ContinueStmt, *ast.NextStmt, *ast.NextfileStmt:
		return true
	case *ast.ExitStmt:
		return walkAwkOptExpr(n.Status)
	case *ast.DeleteStmt:
		return walkAwkExprs(n.Index)
	case *ast.ReturnStmt:
		// ReturnStmt only appears inside user functions, which we already
		// rejected at the top of classifyAwkProgram. Reach it only via a
		// malformed program or future parser change — reject conservatively.
		return false
	case *ast.BlockStmt:
		return walkAwkStmts(n.Body)
	default:
		failLoud("unknown awk stmt kind: %T", s)
		return false // unreachable
	}
}

func walkAwkExprs(es []ast.Expr) bool {
	for _, e := range es {
		if !walkAwkExpr(e) {
			return false
		}
	}
	return true
}

func walkAwkOptExpr(e ast.Expr) bool {
	if e == nil {
		return true
	}
	return walkAwkExpr(e)
}

func walkAwkOptStmt(s ast.Stmt) bool {
	if s == nil {
		return true
	}
	return walkAwkStmt(s)
}

func walkAwkExpr(e ast.Expr) bool {
	switch n := e.(type) {
	case *ast.FieldExpr:
		return walkAwkExpr(n.Index)
	case *ast.NamedFieldExpr:
		return walkAwkExpr(n.Field)
	case *ast.UnaryExpr:
		return walkAwkExpr(n.Value)
	case *ast.BinaryExpr:
		return walkAwkExpr(n.Left) && walkAwkExpr(n.Right)
	case *ast.InExpr:
		return walkAwkExprs(n.Index)
	case *ast.CondExpr:
		return walkAwkExpr(n.Cond) && walkAwkExpr(n.True) && walkAwkExpr(n.False)
	case *ast.NumExpr, *ast.StrExpr, *ast.RegExpr, *ast.VarExpr:
		return true
	case *ast.IndexExpr:
		return walkAwkExprs(n.Index)
	case *ast.AssignExpr:
		return walkAwkExpr(n.Left) && walkAwkExpr(n.Right)
	case *ast.AugAssignExpr:
		return walkAwkExpr(n.Left) && walkAwkExpr(n.Right)
	case *ast.IncrExpr:
		return walkAwkExpr(n.Expr)
	case *ast.CallExpr:
		if !awkBuiltinAllowed(n.Func) {
			return false
		}
		return walkAwkExprs(n.Args)
	case *ast.UserCallExpr:
		return false
	case *ast.MultiExpr:
		return walkAwkExprs(n.Exprs)
	case *ast.GetlineExpr:
		if n.Command != nil || n.File != nil {
			return false
		}
		return walkAwkOptExpr(n.Target)
	case *ast.GroupingExpr:
		return walkAwkExpr(n.Expr)
	default:
		failLoud("unknown awk expr kind: %T", e)
		return false // unreachable
	}
}

// awkBuiltinAllowed reports whether a builtin function token is on the safe
// list. Strict positive whitelist: every allowed builtin is enumerated, and
// system / getline / close / fflush are deliberately omitted (they can run
// subprocesses or write files). Numeric / string / regex builtins are pure
// w.r.t. the file system.
func awkBuiltinAllowed(tok lexer.Token) bool {
	switch tok {
	case lexer.F_LENGTH, lexer.F_SUBSTR, lexer.F_SPRINTF,
		lexer.F_TOLOWER, lexer.F_TOUPPER,
		lexer.F_GSUB, lexer.F_SUB, lexer.F_MATCH,
		lexer.F_SPLIT, lexer.F_INDEX,
		lexer.F_ATAN2, lexer.F_COS, lexer.F_EXP, lexer.F_INT,
		lexer.F_LOG, lexer.F_RAND, lexer.F_SIN, lexer.F_SQRT, lexer.F_SRAND:
		return true
	default:
		return false
	}
}
