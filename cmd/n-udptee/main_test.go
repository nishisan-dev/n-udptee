package main

import (
	"bytes"
	"testing"
)

func TestCLI(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"version"}, {"check", "-c", "../../configs/example.yaml"}} {
		var out, err bytes.Buffer
		if e := execute(args, &out, &err); e != nil {
			t.Fatal(e)
		}
		if out.Len() == 0 {
			t.Fatal("missing output")
		}
	}
	for _, args := range [][]string{{"invalid"}, {"check"}, {"run", "-c", "missing"}, {"check", "-c", "../../configs/example.yaml", "extra"}} {
		if e := execute(args, &bytes.Buffer{}, &bytes.Buffer{}); e == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
}
