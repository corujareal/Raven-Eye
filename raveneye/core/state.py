from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Any
@dataclass
class RavenState:
    values: dict[str,Any]=field(default_factory=dict)
    _lock: asyncio.Lock=field(default_factory=asyncio.Lock,repr=False)
    async def set(self,key:str,value:Any)->None:
        async with self._lock: self.values[key]=value
    async def get(self,key:str,default:Any=None)->Any:
        async with self._lock: return self.values.get(key,default)
