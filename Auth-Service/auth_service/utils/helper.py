from pathlib import Path

def load_key(path: Path) -> str:
    try:
        with open(path, "r") as file:
            return file.read()
    except FileNotFoundError:
        raise RuntimeError(f"Key not found: {path}")
    except Exception as e:
        raise RuntimeError(f"Error loading key {path}: {str(e)}")