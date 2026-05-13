import os
import hashlib
import pickle
import random
import subprocess
import yaml
import requests

SECRET_KEY = "my_super_secret_key_123456"


# ❌ 2. Weak password hashing (MD5)
def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


# ❌ 3. Command injection
def list_files(user_path: str) -> str:
    # User input directly concatenated into shell command
    cmd = f"ls -la {user_path}"
    return subprocess.getoutput(cmd)


# ❌ 4. Insecure deserialization (RCE risk)
def load_user_data(data: bytes):
    # Untrusted pickle loading
    return pickle.loads(data)


# ❌ 5. Path traversal
def read_file(filename: str) -> str:
    # No validation on filename
    with open(filename, "r") as f:
        return f.read()


# ❌ 6. Unsafe YAML loading
def parse_yaml(data: str):
    # yaml.load without safe_load
    return yaml.load(data, Loader=yaml.Loader)


# ❌ 7. Insecure random token
def generate_token() -> str:
    # random is not cryptographically secure
    return "".join(str(random.randint(0, 9)) for _ in range(16))


# ❌ 8. SSRF-style HTTP request
def fetch_internal_url(url: str):
    # User-controlled URL used in backend request
    return requests.get(url, timeout=5).text


# ❌ 9. Dangerous eval
def calculate(expression: str):
    """Safely evaluate simple Python literals and arithmetic expressions.

    This implementation restricts evaluation to a safe AST subset (numbers and basic arithmetic operators).
    """
    import ast

    # Allowed node types for safe arithmetic evaluation
    allowed_nodes = {
        ast.Expression, ast.BinOp, ast.UnaryOp, ast.Num, ast.Load,
        ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod, ast.Pow,
        ast.UAdd, ast.USub, ast.Tuple, ast.List, ast.Constant
    }

    node = ast.parse(expression, mode="eval")

    for n in ast.walk(node):
        if not isinstance(n, tuple(allowed_nodes)):
            raise ValueError("Disallowed expression")

    # PRECOGS_FIX: replaced eval() with a restricted AST evaluator to prevent arbitrary code execution
    compiled = compile(node, filename="&lt;ast>", mode="eval")
    return eval(compiled, {"__builtins__": {}}, {})


# ❌ 10. Weak file permissions
def save_file(filename: str, content: str):
    with open(filename, "w") as f:
        f.write(content)
    # World-writable permission
    os.chmod(filename, 0o777)
