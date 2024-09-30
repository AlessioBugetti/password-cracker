#!/usr/bin/env python3
import os
import subprocess
import re

GREEN = '\033[32m'
RED = '\033[31m'
RESET = '\033[0m'

def run_tests():
    test_dir = 'src/test'
    build_test_dir = 'build/src/test'

    test_files = [f for f in os.listdir(test_dir) if f.endswith('.cc')]

    executables = [f.replace('.cc', '') for f in test_files]

    for executable in executables:
        executable_path = os.path.join(build_test_dir, executable)
        if os.path.isfile(executable_path) and os.access(executable_path, os.X_OK):

            test_result = subprocess.run(executable_path, capture_output=True, text=True)

            output_lines = test_result.stdout.splitlines()
            overall_passed = True

            passed_tests = []
            failed_tests = set()

            for line in output_lines:
                if "[       OK ]" in line:
                    match = re.search(r'\[       OK \] .*?\.(.+?) \(', line)
                    if match:
                        test_name = match.group(1).strip()
                        passed_tests.append(test_name)
                elif "[  FAILED  ]" in line:
                    overall_passed = False
                    match = re.search(r'\[  FAILED  \] .*?\.(.+?) \(', line)
                    if match:
                        test_name = match.group(1).strip()
                        failed_tests.add(test_name)

            if overall_passed:
                print(f"[{GREEN}PASSED{RESET}] {executable}")
            else:
                print(f"[{RED}FAILED{RESET}] {executable}")

            for test in passed_tests:
                print(f"         [{GREEN}PASSED{RESET}] {test}")

            for test in failed_tests:
                print(f"         [{RED}FAILED{RESET}] {test}")

        else:
            print(f"Executable {executable} not found in {build_test_dir}.")

if __name__ == "__main__":
    run_tests()
