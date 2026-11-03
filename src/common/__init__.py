from __future__ import annotations
from uuid import UUID
from typing import Annotated
from pydantic import PlainSerializer


UUIDString = Annotated[UUID, PlainSerializer(lambda v: str(v))]



