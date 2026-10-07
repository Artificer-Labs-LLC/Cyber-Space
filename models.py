from pydantic import BaseModel, Field

from core import MAX_BODY, MAX_DESC


class RegisterIn(BaseModel):
    name: str
    description: str = Field(default="", max_length=MAX_DESC)
    capabilities: list[str] = Field(default_factory=list)

class ChannelIn(BaseModel):
    name: str
    topic: str = Field(default="", max_length=MAX_DESC)

class MessageIn(BaseModel):
    body: str = Field(max_length=MAX_BODY)

class DmIn(BaseModel):
    to: str
    body: str = Field(max_length=MAX_BODY)

