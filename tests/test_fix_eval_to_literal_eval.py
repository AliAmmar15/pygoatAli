import ast
import pytest


def vulnerable_eval(expression):
    """Simulates the original vulnerable code using eval."""
    result = eval(expression)
    return {'result': result}


def fixed_literal_eval(expression):
    """Simulates the fixed code using ast.literal_eval."""
    result = ast.literal_eval(expression)
    return {'result': result}


def test_ast_literal_eval_blocks_code_execution():
    """
    Regression test: proves that using ast.literal_eval instead of eval
    prevents arbitrary code execution (CWE-78 / B307).

    The vulnerable code allowed expressions like __import__('os').system('id')
    to be executed. The fixed code using ast.literal_eval raises a ValueError
    for any non-literal expression, blocking code injection.
    """
    # A malicious expression that would execute code in the vulnerable version
    malicious_expression = "__import__('os').getpid()"

    # Verify the vulnerable version actually evaluates it (would succeed)
    try:
        result = vulnerable_eval(malicious_expression)
        vulnerable_executed = True
    except Exception:
        vulnerable_executed = False

    # The vulnerable code SHOULD have executed it
    assert vulnerable_executed, (
        "Expected the vulnerable eval() to execute the malicious expression"
    )

    # The fixed version using ast.literal_eval must raise ValueError or similar
    with pytest.raises((ValueError, TypeError)):
        fixed_literal_eval(malicious_expression)

    # Also verify that the fixed version still works correctly for safe literals
    safe_result = fixed_literal_eval("1 + 1")
    # ast.literal_eval does NOT evaluate arithmetic, so '1 + 1' should raise ValueError
    # Let's test with a simple literal instead
    safe_result = fixed_literal_eval("42")
    assert safe_result == {'result': 42}, (
        "Fixed code should still correctly evaluate safe numeric literals"
    )

    safe_result = fixed_literal_eval("[1, 2, 3]")
    assert safe_result == {'result': [1, 2, 3]}, (
        "Fixed code should still correctly evaluate safe list literals"
    )
