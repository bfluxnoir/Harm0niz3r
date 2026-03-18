# Backward-compatibility shim.
# The canonical implementation lives in parsers/harmonyos_parser.py.
# Existing imports (e.g. `from harmonyos_parser import parse_app_dump_string`)
# continue to work without any changes.
from parsers.harmonyos_parser import parse_app_dump_string  # noqa: F401
