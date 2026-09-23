"""Point d'entrée installable. Relance avec les droits root, comme orbite-scan.sh."""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    needs_root = sys.platform != "win32" and hasattr(os, "geteuid") and os.geteuid() != 0
    if needs_root and sys.argv[1:] not in (["-h"], ["--help"], ["-V"], ["--version"]):
        os.execvp(
            "sudo",
            ["sudo", "-E", sys.executable, str(ROOT / "__main__.py"), *sys.argv[1:]],
        )
    import importlib.util

    spec = importlib.util.spec_from_file_location("orbite_cli", ROOT / "__main__.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["orbite_cli"] = module
    spec.loader.exec_module(module)
    runtime = sys.modules["__main__"]
    if not hasattr(runtime, "__version__"):
        runtime.__version__ = module.__version__
    module.main()


if __name__ == "__main__":
    main()
