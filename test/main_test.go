package test

import (
	"flag"
	"os"
	"testing"
)

var (
	persist bool
	testID  string
	outPath string
)

func TestMain(m *testing.M) {
	flag.BoolVar(&persist, "persist", false, "persist input files for debugging")
	flag.StringVar(&testID, "test-id", "", "id for persisted files")
	flag.StringVar(&outPath, "path", "../artifacts", "directory to persist input files")
	flag.Parse()

	os.Exit(m.Run())
}
