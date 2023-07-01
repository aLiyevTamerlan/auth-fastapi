from typing import Optional

from fastapi import HTTPException
from pydantic import BaseModel
from pydantic import constr
from pydantic import EmailStr
from pydantic import validator


class TunedModel(BaseModel):
    class Config:

        orm_mode = True


class ShowUser(TunedModel):

    name: str
    surname: str
    email: EmailStr

class UserCreate(BaseModel):
    name: str
    surname: str
    email: EmailStr
    hashed_password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str