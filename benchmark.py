#!/usr/bin/env python3
import subprocess

def run_decryption_program(arguments):
    try:
        # Construct the command to execute
        command = ["./build/decryption-benchmark"] + arguments

        # Run the command
        result = subprocess.run(command, text=True, capture_output=True)

        # Print the output from the program
        print("./decrypt-benchmark", " ".join(arguments))
        if(result.stdout):
            print(result.stdout.strip())
        if(result.stderr):
            print(result.stderr)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    run_decryption_program(["--numExecutions=2", "--numThreads=4"])