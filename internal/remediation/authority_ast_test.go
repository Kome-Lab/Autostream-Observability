package remediation

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestProductionRuntimeHasNoHostExecutorOrUpdaterClient(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate remediation package")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	fileSet := token.NewFileSet()
	var sawConfigure, sawMigration bool
	for _, root := range []string{filepath.Join(repositoryRoot, "cmd"), filepath.Join(repositoryRoot, "internal")} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range parsed.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				if importPath == "os/exec" || strings.Contains(importPath, "autostream-updater") || strings.HasSuffix(importPath, "/updateagent") {
					t.Fatalf("production runtime imports forbidden execution authority %q from %s", importPath, path)
				}
			}

			parsed, err = parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				owner, _ := selector.X.(*ast.Ident)
				if owner == nil {
					return true
				}
				qualified := owner.Name + "." + selector.Sel.Name
				switch qualified {
				case "os.StartProcess", "syscall.Exec", "syscall.ForkExec":
					t.Fatalf("production runtime calls forbidden host execution primitive %s from %s", qualified, path)
				case "control.RunConfigureCommand":
					sawConfigure = true
				case "database.RunEmbeddedMigrations":
					sawMigration = true
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !sawConfigure || !sawMigration {
		t.Fatalf("oracle fixture incomplete: configure=%t migration=%t", sawConfigure, sawMigration)
	}
}
