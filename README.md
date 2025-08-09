# Task-1
#!/usr/bin/env python3
"""
File Integrity Checker
Monitors files for unauthorized changes using SHA-256 hashes
"""

import os
import hashlib
import json
import sys
import argparse
from datetime import datetime
from pathlib import Path

DEFAULT_BASELINE = "file_integrity_baseline.json"
HASH_ALGORITHM = "sha256"
CHUNK_SIZE = 65536  # 64KB chunks for reading files

class FileIntegrityChecker:
    def __init__(self, baseline_file=DEFAULT_BASELINE):
        self.baseline_file = baseline_file
        self.baseline_data = self._load_baseline()
        
    def _load_baseline(self):
        """Load the baseline hash data from file"""
        if os.path.exists(self.baseline_file):
            with open(self.baseline_file, 'r') as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    print(f"Error: Corrupted baseline file {self.baseline_file}")
                    return {}
        return {}
    
    def _save_baseline(self):
        """Save the current baseline to file"""
        with open(self.baseline_file, 'w') as f:
            json.dump(self.baseline_data, f, indent=2)
    
    def _calculate_hash(self, file_path):
        """Calculate the hash of a file"""
        hasher = hashlib.new(HASH_ALGORITHM)
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(CHUNK_SIZE):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, PermissionError) as e:
            print(f"Warning: Could not read {file_path} - {str(e)}")
            return None
    
    def create_baseline(self, target_paths, exclude_dirs=None, exclude_extensions=None):
        """
        Create a new baseline by scanning specified paths
        
        Args:
            target_paths (list): List of files/directories to monitor
            exclude_dirs (list): Directories to exclude
            exclude_extensions (list): File extensions to exclude
        """
        if exclude_dirs is None:
            exclude_dirs = []
        if exclude_extensions is None:
            exclude_extensions = []
        
        self.baseline_data = {
            'metadata': {
                'created': datetime.now().isoformat(),
                'hash_algorithm': HASH_ALGORITHM,
                'excluded_dirs': exclude_dirs,
                'excluded_extensions': exclude_extensions
            },
            'files': {}
        }
        
        for path in target_paths:
            path = os.path.abspath(path)
            if os.path.isfile(path):
                self._add_file_to_baseline(path)
            elif os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclude_dirs]
                    
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Skip excluded extensions
                        if not any(file_path.endswith(ext) for ext in exclude_extensions):
                            self._add_file_to_baseline(file_path)
        
        self._save_baseline()
        print(f"Created new baseline with {len(self.baseline_data['files'])} files")
    
    def _add_file_to_baseline(self, file_path):
        """Add a file's hash to the baseline"""
        file_hash = self._calculate_hash(file_path)
        if file_hash is not None:
            file_stat = os.stat(file_path)
            self.baseline_data['files'][file_path] = {
                'hash': file_hash,
                'size': file_stat.st_size,
                'modified': file_stat.st_mtime,
                'permissions': oct(file_stat.st_mode)[-4:]
            }
    
    def verify_integrity(self, verbose=False):
        """Verify current files against the baseline"""
        if not self.baseline_data:
            print("Error: No baseline data loaded")
            return False
        
        current_files = set()
        changed_files = []
        new_files = []
        missing_files = []
        
        # Check all files in the baseline
        for file_path, file_data in self.baseline_data['files'].items():
            current_files.add(file_path)
            
            if not os.path.exists(file_path):
                missing_files.append(file_path)
                continue
            
            current_hash = self._calculate_hash(file_path)
            if current_hash is None:
                continue  # Error already printed by _calculate_hash
            
            file_stat = os.stat(file_path)
            issues = []
            
            if current_hash != file_data['hash']:
                issues.append("content modified")
            if file_stat.st_size != file_data['size']:
                issues.append("size changed")
            if abs(file_stat.st_mtime - file_data['modified']) > 1:
                issues.append("modification time changed")
            if oct(file_stat.st_mode)[-4:] != file_data['permissions']:
                issues.append("permissions changed")
            
            if issues:
                changed_files.append((file_path, issues))
        
        # Check for new files (not in baseline)
        target_paths = set()
        for file_path in self.baseline_data['files']:
            target_paths.add(os.path.dirname(file_path))
        
        exclude_dirs = self.baseline_data['metadata'].get('excluded_dirs', [])
        exclude_extensions = self.baseline_data['metadata'].get('excluded_extensions', [])
        
        for path in target_paths:
            if os.path.isdir(path):
                for root, dirs, files in os.walk(path):
                    dirs[:] = [d for d in dirs if os.path.join(root, d) not in exclude_dirs]
                    for file in files:
                        file_path = os.path.join(root, file)
                        if (file_path not in current_files and 
                            not any(file_path.endswith(ext) for ext in exclude_extensions)):
                            new_files.append(file_path)
        
        # Report findings
        if verbose or changed_files or new_files or missing_files:
            print("\nFile Integrity Report")
            print("====================")
            print(f"Baseline created: {self.baseline_data['metadata']['created']}")
            print(f"Verification time: {datetime.now().isoformat()}")
            print(f"Files in baseline: {len(self.baseline_data['files'])}")
            
            if changed_files:
                print("\nChanged files:")
                for file_path, issues in changed_files:
                    print(f"  - {file_path}")
                    for issue in issues:
                        print(f"    ! {issue}")
            
            if new_files:
                print("\nNew files (not in baseline):")
                for file_path in new_files:
                    print(f"  + {file_path}")
            
            if missing_files:
                print("\nMissing files (in baseline but not found):")
                for file_path in missing_files:
                    print(f"  x {file_path}")
            
            if not (changed_files or new_files or missing_files):
                print("\nNo changes detected - all files match the baseline")
        
        return not (changed_files or new_files or missing_files)
    
    def update_baseline(self, file_paths=None):
        """
        Update the baseline with current file hashes
        If file_paths is None, updates all files in baseline
        """
        if not self.baseline_data:
            print("Error: No baseline data loaded")
            return
        
        if file_paths is None:
            file_paths = list(self.baseline_data['files'].keys())
        
        updated_count = 0
        for file_path in file_paths:
            if file_path in self.baseline_data['files']:
                self._add_file_to_baseline(file_path)
                updated_count += 1
        
        self.baseline_data['metadata']['updated'] = datetime.now().isoformat()
        self._save_baseline()
        print(f"Updated baseline for {updated_count} files")

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Checker - Monitor files for unauthorized changes",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '--create',
        metavar='PATH',
        nargs='+',
        help='Create new baseline for specified files/directories'
    )
    parser.add_argument(
        '--exclude-dirs',
        metavar='DIR',
        nargs='+',
        default=[],
        help='Directories to exclude when creating baseline'
    )
    parser.add_argument(
        '--exclude-extensions',
        metavar='EXT',
        nargs='+',
        default=[],
        help='File extensions to exclude when creating baseline'
    )
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify files against baseline'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show detailed output during verification'
    )
    parser.add_argument(
        '--update',
        metavar='FILE',
        nargs='*',
        help='Update baseline for specified files (all if none specified)'
    )
    parser.add_argument(
        '--baseline',
        default=DEFAULT_BASELINE,
        help='Specify alternative baseline file'
    )
    
    args = parser.parse_args()
    
    checker = FileIntegrityChecker(args.baseline)
    
    if args.create:
        checker.create_baseline(
            args.create,
            exclude_dirs=args.exclude_dirs,
            exclude_extensions=args.exclude_extensions
        )
    elif args.verify:
        if not checker.verify_integrity(verbose=args.verbose):
            sys.exit(1)  # Exit with error code if changes detected
    elif args.update is not None:  # Checks if flag was present (empty list is valid)
        checker.update_baseline(args.update if args.update else None)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
