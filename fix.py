#!/usr/bin/env python3
"""
Complete Line Ending Fixer for Rust Projects
Removes ALL carriage return characters from all Rust source files
"""

import os
import sys
from pathlib import Path

def fix_line_endings(file_path):
    """Fix line endings in a single file"""
    try:
        # Read file in binary mode
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Check if file has CR characters
        if b'\r' not in content:
            return False, "Already clean"
        
        # Count CRs
        cr_count = content.count(b'\r')
        
        # Remove ALL carriage returns
        # First replace CRLF with LF, then any remaining CR with LF
        clean_content = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
        
        # Write back
        with open(file_path, 'wb') as f:
            f.write(clean_content)
        
        # Verify
        with open(file_path, 'rb') as f:
            verify = f.read()
        
        if b'\r' in verify:
            return False, f"FAILED: Still has CR characters"
        
        return True, f"Fixed ({cr_count} CRs removed)"
    
    except Exception as e:
        return False, f"Error: {str(e)}"

def main():
    print("=" * 70)
    print("Rust Line Ending Fixer - Complete CR Removal")
    print("=" * 70)
    print()
    
    # Check if we're in a Rust project
    if not Path("Cargo.toml").exists():
        print("❌ ERROR: Cargo.toml not found!")
        print("   Please run this script from your Rust project root directory.")
        print()
        print("Usage:")
        print("  cd /path/to/rustynets")
        print("  python3 fix_line_endings.py")
        sys.exit(1)
    
    # Get project name
    try:
        with open("Cargo.toml") as f:
            for line in f:
                if line.startswith("name ="):
                    project_name = line.split('"')[1]
                    break
        print(f"✓ Found project: {project_name}")
    except:
        print("✓ Found Rust project")
    
    print()
    
    # Find all Rust files
    rust_files = list(Path(".").rglob("*.rs"))
    
    # Exclude target directory
    rust_files = [f for f in rust_files if "target" not in str(f)]
    
    print(f"[*] Found {len(rust_files)} Rust source files")
    print()
    
    # Fix each file
    fixed_count = 0
    skipped_count = 0
    failed_count = 0
    
    for file_path in rust_files:
        success, message = fix_line_endings(file_path)
        
        if success:
            print(f"   ✓ {file_path}: {message}")
            fixed_count += 1
        elif "Already clean" in message:
            skipped_count += 1
        else:
            print(f"   ✗ {file_path}: {message}")
            failed_count += 1
    
    print()
    print("=" * 70)
    print("Summary")
    print("=" * 70)
    print(f"Total files: {len(rust_files)}")
    print(f"Fixed: {fixed_count}")
    print(f"Already clean: {skipped_count}")
    print(f"Failed: {failed_count}")
    print("=" * 70)
    print()
    
    if fixed_count > 0:
        print("✅ Line endings fixed!")
        print()
        print("Next steps:")
        print("  1. cargo clean")
        print("  2. cargo build --release")
        print()
    elif failed_count > 0:
        print("⚠ Some files failed to fix. Please check errors above.")
        sys.exit(1)
    else:
        print("✅ All files already have correct line endings!")
        print()
        print("If you're still getting errors, try:")
        print("  1. cargo clean")
        print("  2. rm -rf target/")
        print("  3. cargo build --release")
        print()

if __name__ == "__main__":
    main()
