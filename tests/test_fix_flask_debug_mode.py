import ast
import os

def test_flask_debug_mode_disabled():
    """
    Regression test: Ensures the Flask app is not run with debug=True.
    The vulnerable code had debug=True which exposes the Werkzeug debugger
    and allows arbitrary code execution (CWE-94, B201).
    The fixed code uses debug=False.
    """
    app_file = os.path.join(
        os.path.dirname(__file__),
        'dockerized_labs', 'broken_auth_lab', 'app.py'
    )

    # If the file doesn't exist relative to test location, try the absolute path
    if not os.path.exists(app_file):
        app_file = '/tmp/velonus-scan-9a8tp8tp/AliAmmar15-pygoatAli-19d17cc/dockerized_labs/broken_auth_lab/app.py'

    assert os.path.exists(app_file), f"app.py not found at {app_file}"

    with open(app_file, 'r') as f:
        source = f.read()

    tree = ast.parse(source)

    debug_true_found = False

    for node in ast.walk(tree):
        # Look for app.run(...) calls
        if isinstance(node, ast.Call):
            func = node.func
            # Match attribute calls like app.run(...)
            if isinstance(func, ast.Attribute) and func.attr == 'run':
                for keyword in node.keywords:
                    if keyword.arg == 'debug':
                        value = keyword.value
                        # Check if debug=True (vulnerable)
                        if isinstance(value, ast.Constant) and value.value is True:
                            debug_true_found = True
                        elif isinstance(value, ast.NameConstant) and value.value is True:
                            # For older Python AST compatibility
                            debug_true_found = True

    assert not debug_true_found, (
        "SECURITY VULNERABILITY: Flask app.run() is called with debug=True. "
        "This exposes the Werkzeug debugger and allows arbitrary code execution. "
        "Set debug=False for production use."
    )
