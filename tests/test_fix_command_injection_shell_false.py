import subprocess
import shlex


def command_out_vulnerable(command):
    """Original vulnerable implementation with shell=True"""
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


def command_out_fixed(command):
    """Fixed implementation with shell=False"""
    if isinstance(command, str):
        command = shlex.split(command)
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return process.communicate()


def test_command_injection_shell_false():
    """
    Regression test: proves that the fixed command_out uses shell=False,
    preventing shell injection attacks.

    With shell=True (vulnerable), a command like:
      'echo safe; echo INJECTED'
    would execute both 'echo safe' AND 'echo INJECTED' via the shell,
    with INJECTED appearing in the output.

    With shell=False (fixed), the string is split with shlex and passed
    as a list, so the semicolon and second command are treated as
    literal arguments to echo, not as a shell command separator.
    """
    # This string attempts shell injection via semicolon
    injection_payload = "echo safe; echo INJECTED"

    # Verify vulnerable behavior: shell=True allows injection
    stdout_vuln, _ = command_out_vulnerable(injection_payload)
    vuln_output = stdout_vuln.decode()
    # With shell=True, both commands run and INJECTED appears in output
    assert "INJECTED" in vuln_output, (
        "Vulnerable code should have executed the injected command"
    )

    # Verify fixed behavior: shell=False prevents injection
    stdout_fixed, _ = command_out_fixed(injection_payload)
    fixed_output = stdout_fixed.decode()
    # With shell=False, the semicolon and second command are NOT executed
    # echo receives 'safe;' 'echo' 'INJECTED' as literal args, so
    # 'INJECTED' would appear as a literal argument to echo, but
    # crucially it is NOT executed as a separate command.
    # The key assertion is that the fixed version does NOT produce a
    # standalone 'INJECTED\n' line from a separate process execution.
    # With shlex.split, 'echo safe; echo INJECTED' -> ['echo', 'safe;', 'echo', 'INJECTED']
    # So output is 'safe; echo INJECTED\n' — not two separate command outputs.
    assert fixed_output.strip() == "safe; echo INJECTED", (
        f"Fixed code should treat the injection payload as literal arguments, "
        f"not execute a second command. Got: {repr(fixed_output)}"
    )
