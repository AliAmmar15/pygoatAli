import subprocess
import shlex
import sys


# Implementation of the fixed function
def command_out_fixed(command):
    if isinstance(command, str):
        command = shlex.split(command)
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


# Implementation of the vulnerable function
def command_out_vulnerable(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


def test_command_injection_prevented_by_shell_false():
    """
    Regression test for CWE-78 / B602:
    The vulnerable code uses shell=True, allowing shell injection via metacharacters.
    The fixed code uses shell=False (with shlex.split), preventing injection.

    We demonstrate that a command injection payload that works with shell=True
    does NOT execute the injected part when shell=False is used.
    """
    # Craft a command with shell injection: the injected part writes to a file
    # Using 'echo' which is safe and cross-platform on Linux/Mac
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as tmp:
        injected_file = tmp.name

    # Remove the file so we can check if it gets created by injection
    if os.path.exists(injected_file):
        os.unlink(injected_file)

    try:
        # Injection payload: base command is 'echo hello', injected part creates a file
        injection_payload = f"echo hello; touch {injected_file}"

        # With the FIXED code (shell=False), the injected command should NOT run
        stdout, stderr = command_out_fixed(injection_payload)

        # The injected file should NOT have been created
        assert not os.path.exists(injected_file), (
            "Security fix FAILED: shell injection was able to create a file even with shell=False. "
            "The 'touch' command should not have executed."
        )

        # The output should contain the literal semicolon and everything as one argument
        # (i.e., echo treated the whole string as its argument, not as a shell command)
        # This confirms shell=False is in effect
        output = stdout.decode()
        # With shell=False and shlex.split, 'echo' gets: ['echo', 'hello;', 'touch', injected_file]
        # echo will print all those tokens separated by spaces
        assert 'hello' in output, "Expected 'echo' command output to contain 'hello'"

    finally:
        # Cleanup
        if os.path.exists(injected_file):
            os.unlink(injected_file)
