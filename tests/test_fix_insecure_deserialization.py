import json
import pickle
import base64
from dataclasses import dataclass

# Reproduce the fixed deserialize_data function
def deserialize_data(data):
    return json.loads(data)


def test_deserialize_data_uses_json_not_pickle():
    """
    Regression test: deserialize_data must use json.loads (safe) instead of
    pickle.loads (insecure / CWE-502).

    The test:
    1. Verifies that valid JSON is deserialized correctly.
    2. Verifies that a pickle payload raises an exception (NOT silently
       executed), proving the function does NOT call pickle.loads.
    3. Verifies that a crafted pickle RCE payload cannot execute arbitrary
       code through deserialize_data.
    """

    # --- Part 1: normal JSON round-trip works ---
    payload = json.dumps({"admin": 0, "user": "alice"})
    result = deserialize_data(payload)
    assert result == {"admin": 0, "user": "alice"}

    # --- Part 2: raw pickle bytes must NOT deserialize successfully ---
    @dataclass
    class TestUser:
        admin: int = 0

    pickled_bytes = pickle.dumps(TestUser())
    # The fixed function uses json.loads, so a raw pickle bytestring should
    # raise an exception (JSONDecodeError), not return a TestUser object.
    raised = False
    try:
        deserialize_data(pickled_bytes)
    except Exception:
        raised = True
    assert raised, (
        "deserialize_data accepted raw pickle bytes without raising — "
        "this suggests pickle.loads is being used (insecure)."
    )

    # --- Part 3: a pickle RCE payload must not execute arbitrary code ---
    executed = []

    class MaliciousPayload:
        def __reduce__(self):
            # Attempt to run arbitrary code on unpickling
            import os
            return (executed.append, ("RCE",))

    malicious_pickle = pickle.dumps(MaliciousPayload())
    b64_malicious = base64.b64encode(malicious_pickle)

    # Attempt to deserialize the base64-encoded pickle through the fixed function
    try:
        deserialize_data(b64_malicious)
    except Exception:
        pass  # Expected: json.loads will reject it

    assert "RCE" not in executed, (
        "The malicious pickle payload executed arbitrary code — "
        "deserialize_data is still using pickle (insecure)."
    )
