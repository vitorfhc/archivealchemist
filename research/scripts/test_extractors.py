#!/usr/bin/env python3
"""
Test malicious archives against various extraction libraries in Docker.
Tests Python, Go, Java, Node.js extractors and CLI tools.
"""
import os
import sys
import subprocess
import json
import tempfile

ARCHIVE_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "archives")

###############################################################################
# Python extractor test script (runs inside Docker)
###############################################################################
PYTHON_TEST = r'''
import zipfile
import tarfile
import os
import sys
import traceback

def test_zip_extract(archive_path, output_dir):
    """Test Python's zipfile extraction."""
    results = {}
    try:
        with zipfile.ZipFile(archive_path, 'r') as z:
            names = z.namelist()
            results['namelist'] = names
            results['infolist'] = []
            for info in z.infolist():
                results['infolist'].append({
                    'filename': info.filename,
                    'file_size': info.file_size,
                    'external_attr': info.external_attr,
                })

            # Try extractall
            try:
                z.extractall(output_dir)
                results['extract_status'] = 'SUCCESS'
            except Exception as e:
                results['extract_status'] = f'ERROR: {e}'

            # Check what was extracted
            extracted = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, output_dir)
                    is_link = os.path.islink(fpath)
                    target = os.readlink(fpath) if is_link else None
                    try:
                        content = open(fpath, 'r').read()[:100] if not is_link else None
                    except:
                        content = "<binary>"
                    extracted.append({
                        'path': rel,
                        'is_symlink': is_link,
                        'symlink_target': target,
                        'content_preview': content,
                    })
                for d in dirs:
                    dpath = os.path.join(root, d)
                    rel = os.path.relpath(dpath, output_dir)
                    is_link = os.path.islink(dpath)
                    target = os.readlink(dpath) if is_link else None
                    extracted.append({
                        'path': rel + '/',
                        'is_symlink': is_link,
                        'symlink_target': target,
                        'content_preview': None,
                    })
            results['extracted_files'] = extracted
    except Exception as e:
        results['error'] = str(e)
        results['traceback'] = traceback.format_exc()
    return results

def test_tar_extract(archive_path, output_dir):
    """Test Python's tarfile extraction."""
    results = {}
    try:
        with tarfile.open(archive_path, 'r:*') as t:
            names = t.getnames()
            results['namelist'] = names
            results['members'] = []
            for m in t.getmembers():
                results['members'].append({
                    'name': m.name,
                    'type': m.type,
                    'linkname': m.linkname,
                    'size': m.size,
                    'mode': oct(m.mode),
                })

            # Try extractall
            try:
                t.extractall(output_dir)
                results['extract_status'] = 'SUCCESS'
            except Exception as e:
                results['extract_status'] = f'ERROR: {e}'

            # Check what was extracted
            extracted = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, output_dir)
                    is_link = os.path.islink(fpath)
                    target = os.readlink(fpath) if is_link else None
                    try:
                        content = open(fpath, 'r').read()[:100] if not is_link else None
                    except:
                        content = "<binary>"
                    extracted.append({
                        'path': rel,
                        'is_symlink': is_link,
                        'symlink_target': target,
                        'content_preview': content,
                    })
                for d in dirs:
                    dpath = os.path.join(root, d)
                    rel = os.path.relpath(dpath, output_dir)
                    is_link = os.path.islink(dpath)
                    target = os.readlink(dpath) if is_link else None
                    extracted.append({
                        'path': rel + '/',
                        'is_symlink': is_link,
                        'symlink_target': target,
                        'content_preview': None,
                    })
            results['extracted_files'] = extracted

            # Check if file was written through symlink
            for f in extracted:
                if f.get('is_symlink') and f.get('symlink_target'):
                    target = f['symlink_target']
                    if os.path.exists(target):
                        try:
                            results['symlink_target_content'] = open(target, 'r').read()[:200]
                            results['VULNERABLE_SYMLINK_WRITE'] = True
                        except:
                            pass

    except Exception as e:
        results['error'] = str(e)
        results['traceback'] = traceback.format_exc()
    return results


# Check for files written outside extraction dir
def check_escape(output_dir, check_paths):
    """Check if files were written outside the extraction directory."""
    results = {}
    for p in check_paths:
        exists = os.path.exists(p)
        content = None
        if exists:
            try:
                content = open(p, 'r').read()[:200]
            except:
                content = "<exists but unreadable>"
        results[p] = {'exists': exists, 'content': content}
    return results


import json, tempfile

archive = sys.argv[1]
output_dir = tempfile.mkdtemp(prefix='extract_test_')

escape_check_paths = [
    '/tmp/evil_target.txt',
    '/tmp/evil_via_symlink.txt',
    '/tmp/null_evil.txt',
    '/tmp/backslash_evil.txt',
    '/tmp/unicode_evil.txt',
    '/tmp/overlong_evil.txt',
    '/tmp/mixed_evil.txt',
    '/tmp/symlink_chain_evil.txt',
    '/tmp/dots_evil.txt',
    '/tmp/dots2_evil.txt',
    '/tmp/encoded_evil.txt',
]

if archive.endswith('.zip'):
    result = test_zip_extract(archive, output_dir)
elif archive.endswith('.tar') or archive.endswith('.tar.gz'):
    result = test_tar_extract(archive, output_dir)
else:
    result = {'error': 'Unknown format'}

result['escape_check'] = check_escape(output_dir, escape_check_paths)
print(json.dumps(result, indent=2, default=str))
'''

###############################################################################
# Go extractor test (runs inside Docker)
###############################################################################
GO_ZIP_TEST = r'''
package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <archive> <output_dir>\n", os.Args[0])
		os.Exit(1)
	}
	archive := os.Args[1]
	outputDir := os.Args[2]
	os.MkdirAll(outputDir, 0755)

	result := map[string]interface{}{}

	r, err := zip.OpenReader(archive)
	if err != nil {
		result["error"] = err.Error()
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}
	defer r.Close()

	names := []string{}
	for _, f := range r.File {
		names = append(names, f.Name)
	}
	result["namelist"] = names

	// Extract files
	extracted := []map[string]interface{}{}
	extractErr := ""
	for _, f := range r.File {
		fpath := filepath.Join(outputDir, f.Name)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			extracted = append(extracted, map[string]interface{}{
				"path": f.Name,
				"type": "dir",
			})
			continue
		}

		// Check for symlink
		if f.FileInfo().Mode()&os.ModeSymlink != 0 {
			rc, err := f.Open()
			if err != nil {
				extractErr += fmt.Sprintf("symlink open %s: %v; ", f.Name, err)
				continue
			}
			target, _ := io.ReadAll(rc)
			rc.Close()

			os.MkdirAll(filepath.Dir(fpath), os.ModePerm)
			err = os.Symlink(string(target), fpath)
			if err != nil {
				// Try removing existing
				os.Remove(fpath)
				err = os.Symlink(string(target), fpath)
			}
			extracted = append(extracted, map[string]interface{}{
				"path":           f.Name,
				"type":           "symlink",
				"symlink_target": string(target),
				"symlink_err":    fmt.Sprintf("%v", err),
			})
			continue
		}

		// Regular file
		os.MkdirAll(filepath.Dir(fpath), os.ModePerm)

		rc, err := f.Open()
		if err != nil {
			extractErr += fmt.Sprintf("open %s: %v; ", f.Name, err)
			continue
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			// Could be writing through a symlink
			extractErr += fmt.Sprintf("create %s: %v; ", f.Name, err)
			rc.Close()
			continue
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		content := ""
		if data, err := os.ReadFile(fpath); err == nil {
			if len(data) > 100 {
				content = string(data[:100])
			} else {
				content = string(data)
			}
		}

		extracted = append(extracted, map[string]interface{}{
			"path":            f.Name,
			"type":            "file",
			"content_preview": content,
		})
	}

	result["extracted"] = extracted
	if extractErr != "" {
		result["extract_errors"] = extractErr
	}

	// Check escape paths
	escapeCheck := map[string]interface{}{}
	checkPaths := []string{
		"/tmp/evil_target.txt",
		"/tmp/evil_via_symlink.txt",
		"/tmp/unicode_evil.txt",
		"/tmp/symlink_chain_evil.txt",
	}
	for _, p := range checkPaths {
		if data, err := os.ReadFile(p); err == nil {
			escapeCheck[p] = map[string]interface{}{
				"exists":  true,
				"content": string(data),
			}
		} else {
			escapeCheck[p] = map[string]interface{}{
				"exists": false,
			}
		}
	}
	result["escape_check"] = escapeCheck

	// Check if we have vulnerable patterns
	for _, e := range extracted {
		m := e
		if m["type"] == "symlink" {
			target := fmt.Sprintf("%v", m["symlink_target"])
			if strings.HasPrefix(target, "/") || strings.Contains(target, "..") {
				result["HAS_DANGEROUS_SYMLINK"] = true
			}
		}
		if m["type"] == "file" {
			name := fmt.Sprintf("%v", m["path"])
			if strings.Contains(name, "..") || strings.HasPrefix(name, "/") {
				result["HAS_PATH_TRAVERSAL"] = true
			}
		}
	}

	b, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(b))
}
'''

GO_TAR_TEST = r'''
package main

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <archive> <output_dir>\n", os.Args[0])
		os.Exit(1)
	}
	archive := os.Args[1]
	outputDir := os.Args[2]
	os.MkdirAll(outputDir, 0755)

	result := map[string]interface{}{}

	f, err := os.Open(archive)
	if err != nil {
		result["error"] = err.Error()
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}
	defer f.Close()

	tr := tar.NewReader(f)
	extracted := []map[string]interface{}{}
	extractErr := ""

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			extractErr += fmt.Sprintf("next: %v; ", err)
			break
		}

		target := filepath.Join(outputDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, os.FileMode(header.Mode))
			extracted = append(extracted, map[string]interface{}{
				"name": header.Name,
				"type": "dir",
			})

		case tar.TypeSymlink:
			os.MkdirAll(filepath.Dir(target), 0755)
			os.Remove(target)
			err := os.Symlink(header.Linkname, target)
			extracted = append(extracted, map[string]interface{}{
				"name":           header.Name,
				"type":           "symlink",
				"symlink_target": header.Linkname,
				"err":            fmt.Sprintf("%v", err),
			})

		case tar.TypeReg, tar.TypeRegA:
			os.MkdirAll(filepath.Dir(target), 0755)
			outFile, err := os.Create(target)
			if err != nil {
				extractErr += fmt.Sprintf("create %s: %v; ", header.Name, err)
				continue
			}
			written, _ := io.Copy(outFile, tr)
			outFile.Close()

			content := ""
			if data, err := os.ReadFile(target); err == nil {
				if len(data) > 100 {
					content = string(data[:100])
				} else {
					content = string(data)
				}
			}

			extracted = append(extracted, map[string]interface{}{
				"name":            header.Name,
				"type":            "file",
				"written":         written,
				"content_preview": content,
			})

		case tar.TypeLink:
			linkTarget := filepath.Join(outputDir, header.Linkname)
			os.MkdirAll(filepath.Dir(target), 0755)
			err := os.Link(linkTarget, target)
			extracted = append(extracted, map[string]interface{}{
				"name":        header.Name,
				"type":        "hardlink",
				"link_target": header.Linkname,
				"err":         fmt.Sprintf("%v", err),
			})
		}
	}

	result["extracted"] = extracted
	if extractErr != "" {
		result["extract_errors"] = extractErr
	}

	// Check escape paths
	escapeCheck := map[string]interface{}{}
	checkPaths := []string{
		"/tmp/evil_target.txt",
		"/tmp/evil_via_symlink.txt",
		"/tmp/symlink_chain_evil.txt",
	}
	for _, p := range checkPaths {
		if data, err := os.ReadFile(p); err == nil {
			escapeCheck[p] = map[string]interface{}{
				"exists":  true,
				"content": string(data),
			}
		} else {
			escapeCheck[p] = map[string]interface{}{
				"exists": false,
			}
		}
	}
	result["escape_check"] = escapeCheck

	// Check if vulnerable patterns present
	for _, e := range extracted {
		if e["type"] == "symlink" {
			target := fmt.Sprintf("%v", e["symlink_target"])
			if strings.HasPrefix(target, "/") || strings.Contains(target, "..") {
				result["HAS_DANGEROUS_SYMLINK"] = true
			}
		}
	}

	b, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(b))
}
'''

###############################################################################
# Docker runner
###############################################################################

def run_docker_python(archive_name):
    """Run Python extractor test in Docker."""
    archive_path = os.path.join(ARCHIVE_DIR, archive_name)
    if not os.path.exists(archive_path):
        return {"error": f"Archive not found: {archive_path}"}

    # Write test script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(PYTHON_TEST)
        test_script = f.name

    try:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{archive_path}:/archive/{archive_name}:ro",
            "-v", f"{test_script}:/test.py:ro",
            "python:3.12-slim",
            "python3", "/test.py", f"/archive/{archive_name}"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        try:
            return json.loads(result.stdout)
        except:
            return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    finally:
        os.unlink(test_script)


def run_docker_go_zip(archive_name):
    """Run Go ZIP extractor test in Docker."""
    archive_path = os.path.join(ARCHIVE_DIR, archive_name)
    if not os.path.exists(archive_path):
        return {"error": f"Archive not found: {archive_path}"}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False) as f:
        f.write(GO_ZIP_TEST)
        test_script = f.name

    try:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{archive_path}:/archive/{archive_name}:ro",
            "-v", f"{test_script}:/test.go:ro",
            "golang:1.22",
            "bash", "-c", "cd /tmp && cp /test.go main.go && go run main.go /archive/" + archive_name + " /tmp/out"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        try:
            return json.loads(result.stdout)
        except:
            return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    finally:
        os.unlink(test_script)

def run_docker_go_tar(archive_name):
    """Run Go TAR extractor test in Docker."""
    archive_path = os.path.join(ARCHIVE_DIR, archive_name)
    if not os.path.exists(archive_path):
        return {"error": f"Archive not found: {archive_path}"}

    with tempfile.NamedTemporaryFile(mode='w', suffix='.go', delete=False) as f:
        f.write(GO_TAR_TEST)
        test_script = f.name

    try:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{archive_path}:/archive/{archive_name}:ro",
            "-v", f"{test_script}:/test.go:ro",
            "golang:1.22",
            "bash", "-c", "cd /tmp && cp /test.go main.go && go run main.go /archive/" + archive_name + " /tmp/out"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        try:
            return json.loads(result.stdout)
        except:
            return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}
    finally:
        os.unlink(test_script)


def run_docker_unzip_cli(archive_name):
    """Run unzip CLI tool test in Docker."""
    archive_path = os.path.join(ARCHIVE_DIR, archive_name)
    if not os.path.exists(archive_path):
        return {"error": f"Archive not found: {archive_path}"}

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{archive_path}:/archive/{archive_name}:ro",
        "ubuntu:22.04",
        "bash", "-c",
        f"""
        apt-get update -qq && apt-get install -y -qq unzip > /dev/null 2>&1
        mkdir -p /tmp/out
        echo "=== UNZIP LIST ==="
        unzip -l "/archive/{archive_name}" 2>&1 || true
        echo "=== UNZIP EXTRACT ==="
        cd /tmp/out && unzip -o "/archive/{archive_name}" 2>&1 || true
        echo "=== EXTRACTED FILES ==="
        find /tmp/out -type f -o -type l | while read f; do
            if [ -L "$f" ]; then
                echo "SYMLINK: $f -> $(readlink "$f")"
            else
                echo "FILE: $f ($(head -c 100 "$f"))"
            fi
        done
        echo "=== ESCAPE CHECK ==="
        for p in /tmp/evil_target.txt /tmp/evil_via_symlink.txt /tmp/unicode_evil.txt /tmp/null_evil.txt /tmp/backslash_evil.txt; do
            if [ -f "$p" ]; then
                echo "ESCAPED: $p = $(cat "$p")"
            fi
        done
        """
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}


def run_docker_tar_cli(archive_name):
    """Run tar CLI tool test in Docker."""
    archive_path = os.path.join(ARCHIVE_DIR, archive_name)
    if not os.path.exists(archive_path):
        return {"error": f"Archive not found: {archive_path}"}

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{archive_path}:/archive/{archive_name}:ro",
        "ubuntu:22.04",
        "bash", "-c",
        f"""
        mkdir -p /tmp/out
        echo "=== TAR LIST ==="
        tar -tvf "/archive/{archive_name}" 2>&1 || true
        echo "=== TAR EXTRACT ==="
        cd /tmp/out && tar -xvf "/archive/{archive_name}" 2>&1 || true
        echo "=== EXTRACTED FILES ==="
        find /tmp/out -type f -o -type l 2>/dev/null | while read f; do
            if [ -L "$f" ]; then
                echo "SYMLINK: $f -> $(readlink "$f")"
            else
                echo "FILE: $f ($(head -c 100 "$f"))"
            fi
        done
        echo "=== ESCAPE CHECK ==="
        for p in /tmp/evil_target.txt /tmp/evil_via_symlink.txt /tmp/symlink_chain_evil.txt; do
            if [ -f "$p" ]; then
                echo "ESCAPED: $p = $(cat "$p")"
            fi
        done
        """
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}


###############################################################################
# Main test runner
###############################################################################

def print_result(label, result):
    """Pretty-print a test result."""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    if isinstance(result, dict):
        # Check for vulnerability indicators
        vulnerable = False
        if result.get('VULNERABLE_SYMLINK_WRITE'):
            vulnerable = True
        if result.get('HAS_DANGEROUS_SYMLINK'):
            print("  [!] DANGEROUS SYMLINK DETECTED")
        if result.get('HAS_PATH_TRAVERSAL'):
            print("  [!] PATH TRAVERSAL DETECTED")
            vulnerable = True

        escape = result.get('escape_check', {})
        for path, info in escape.items():
            if isinstance(info, dict) and info.get('exists'):
                print(f"  [!!!] FILE ESCAPED TO: {path}")
                print(f"        Content: {info.get('content', 'N/A')}")
                vulnerable = True

        if 'stdout' in result:
            # CLI output
            stdout = result['stdout']
            if 'ESCAPED:' in stdout:
                vulnerable = True
                for line in stdout.split('\n'):
                    if 'ESCAPED:' in line:
                        print(f"  [!!!] {line.strip()}")

        if vulnerable:
            print("  >>> VULNERABLE <<<")
        else:
            print("  [OK] No escape detected")

        # Print details
        if 'stdout' in result:
            # Truncate for readability
            stdout = result['stdout']
            if len(stdout) > 2000:
                stdout = stdout[:2000] + "\n... (truncated)"
            print(stdout)
        else:
            print(json.dumps(result, indent=2, default=str)[:3000])
    else:
        print(str(result)[:3000])


def main():
    print("=" * 60)
    print("ARCHIVE SECURITY RESEARCH - EXTRACTOR TESTING")
    print("=" * 60)

    # Check Docker is available
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode != 0:
        print("ERROR: Docker not available!")
        sys.exit(1)

    archives = os.listdir(ARCHIVE_DIR)
    print(f"\nFound {len(archives)} test archives in {ARCHIVE_DIR}")
    for a in sorted(archives):
        print(f"  - {a}")

    # Focus on the most promising attack vectors first
    print("\n" + "#" * 60)
    print("# PHASE 1: Symlink attacks (highest chance of finding vulns)")
    print("#" * 60)

    # Test symlink+dupe in TAR (most likely to work)
    print_result("TAR CLI: symlink_dupe.tar", run_docker_tar_cli("symlink_dupe.tar"))
    print_result("TAR CLI: symlink_parent.tar", run_docker_tar_cli("symlink_parent.tar"))
    print_result("TAR CLI: symlink_chain.tar", run_docker_tar_cli("symlink_chain.tar"))

    # Test symlink+dupe in ZIP
    print_result("Python zipfile: symlink_dupe.zip", run_docker_python("symlink_dupe.zip"))
    print_result("Python tarfile: symlink_dupe.tar", run_docker_python("symlink_dupe.tar"))
    print_result("Python tarfile: symlink_chain.tar", run_docker_python("symlink_chain.tar"))
    print_result("Python tarfile: symlink_parent.tar", run_docker_python("symlink_parent.tar"))

    # Test Go extractors
    print("\n" + "#" * 60)
    print("# PHASE 2: Go extractor tests")
    print("#" * 60)
    print_result("Go archive/zip: symlink_dupe.zip", run_docker_go_zip("symlink_dupe.zip"))
    print_result("Go archive/zip: symlink_parent.zip", run_docker_go_zip("symlink_parent.zip"))
    print_result("Go archive/tar: symlink_dupe.tar", run_docker_go_tar("symlink_dupe.tar"))
    print_result("Go archive/tar: symlink_chain.tar", run_docker_go_tar("symlink_chain.tar"))
    print_result("Go archive/tar: symlink_parent.tar", run_docker_go_tar("symlink_parent.tar"))

    print("\n" + "#" * 60)
    print("# PHASE 3: CLI tool tests")
    print("#" * 60)
    print_result("unzip CLI: backslash.zip", run_docker_unzip_cli("backslash.zip"))
    print_result("unzip CLI: unicode_path.zip", run_docker_unzip_cli("unicode_path.zip"))
    print_result("unzip CLI: null_byte.zip", run_docker_unzip_cli("null_byte.zip"))
    print_result("unzip CLI: overlong_utf8.zip", run_docker_unzip_cli("overlong_utf8.zip"))
    print_result("unzip CLI: mixed_slash.zip", run_docker_unzip_cli("mixed_slash.zip"))
    print_result("unzip CLI: symlink_dupe.zip", run_docker_unzip_cli("symlink_dupe.zip"))
    print_result("unzip CLI: symlink_parent.zip", run_docker_unzip_cli("symlink_parent.zip"))


if __name__ == "__main__":
    main()
