package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func CompileLoader(source, outputPath string, profile *Profile) error {
	tmpDir, err := os.MkdirTemp("", "hollow-*")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	srcPath := filepath.Join(tmpDir, profile.Filename)
	if err := os.WriteFile(srcPath, []byte(source), 0600); err != nil {
		return fmt.Errorf("writing source: %w", err)
	}

	args := buildCompilerArgs(srcPath, outputPath, profile)
	fmt.Printf("[+] Compile command: %s %s\n", profile.Compile.Compiler, strings.Join(args, " "))
	cmd := exec.Command(profile.Compile.Compiler, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("compilation failed: %w", err)
	}
	return nil
}

func buildCompilerArgs(srcPath, outputPath string, profile *Profile) []string {
	args := []string{srcPath, "-o", outputPath, "-lbcrypt", "-w"}
	if profile.Compile.Strip {
		args = append(args, "-s")
	}
	if profile.Compile.OutputType == "dll" {
		args = append(args, "-shared", "-nostartfiles", "-static-libgcc")
	} else {
		args = append(args, "-static")
	}

	if profile.Compile.Args != nil {
		args = append(args, profile.Compile.Args...)
	}
	return args
}
