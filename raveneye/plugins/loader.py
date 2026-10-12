from __future__ import annotations
import importlib.metadata
from dataclasses import dataclass
from typing import Any
@dataclass(frozen=True,slots=True)
class Plugin:
    name:str; obj:Any
class PluginLoader:
    """Load RavenEye plugins through the `raveneye.plugins` entry-point group."""
    def discover(self)->list[Plugin]:
        eps=importlib.metadata.entry_points()
        group=eps.select(group='raveneye.plugins') if hasattr(eps,'select') else eps.get('raveneye.plugins',[])
        out=[]
        for ep in group:
            try: out.append(Plugin(ep.name,ep.load()))
            except Exception: continue
        return out
