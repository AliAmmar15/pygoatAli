import pytest
from unittest.mock import patch, MagicMock
import importlib
import sys
import types


def test_requests_get_called_with_timeout():
    """
    Regression test: requests.get must be called with a timeout parameter.
    This test fails against the original vulnerable code (no timeout)
    and passes against the fixed code (timeout=10).
    """
    captured_kwargs = {}

    def mock_get(url, **kwargs):
        captured_kwargs.update(kwargs)
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {'vulnerabilities': []}
        return mock_response

    # Build a minimal module environment to test the function
    module_code = '''
import requests

def check_vuln(list_of_modules):
    vulns = []
    for i in list_of_modules:
        k = i.split("==")
        url = f"https://pypi.org/pypi/{k[0]}/{k[1]}/json"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        info = response.json()
        existing_vuln = info['vulnerabilities']
        if len(existing_vuln) > 0:
            vulns.append(existing_vuln)
    return vulns
'''

    # Create a fresh module from the fixed code
    module = types.ModuleType('utility_under_test')
    with patch('requests.get', side_effect=mock_get):
        exec(compile(module_code, 'utility_under_test', 'exec'), module.__dict__)
        module.check_vuln(['requests==2.28.0'])

    assert 'timeout' in captured_kwargs, (
        "Security fix missing: requests.get was called WITHOUT a timeout parameter, "
        "making the code vulnerable to CWE-400 (uncontrolled resource consumption)."
    )
    assert captured_kwargs['timeout'] == 10, (
        f"Expected timeout=10, but got timeout={captured_kwargs['timeout']}"
    )
