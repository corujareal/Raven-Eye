import sys, types
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
if "colorama" not in sys.modules:
    m=types.ModuleType("colorama")
    class _C:
        def __getattr__(self, name): return ""
    m.Fore=_C(); m.Style=_C(); m.init=lambda *a,**k: None
    sys.modules["colorama"]=m
