from datetime import datetime

from pydantic import BaseModel, EmailStr, constr


class UserBaseSchema(BaseModel):
    name: str
    email: EmailStr

    class Config:
        orm_mode = True


class CreateUserSchema(UserBaseSchema):
    password: str
    passwordConfirm: str


class LoginUserSchema(BaseModel):
    email: EmailStr
    password: str


class UserResponse(UserBaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime
