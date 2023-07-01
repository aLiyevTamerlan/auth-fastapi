from typing import Union
import hashing, settings, security, utils
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from sqlalchemy.orm import Session
from schemas.user_schema import ShowUser, UserCreate, Token
from db.session import get_db
from db.models import User
app = FastAPI(title="Auth API", openapi_url="/openapi.json")

    
@app.post('/create-user')
def create_user(body: UserCreate, db: Session=Depends(get_db)):
    body.hashed_password = hashing.Hasher.get_password_hash(body.hashed_password)
    obj_data = jsonable_encoder(body)
    us = User(**obj_data)
    db.add(us)
    db.commit()
    db.refresh(us)

    return []

@app.post("/token", response_model = Token)
def login_for_access_token(response: Response,  form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):

    user = utils.authenticate_user(username = form_data.username, db = db, password=form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires,
    )
    refresh_token_expires = timedelta(minutes=settings.REFRESH_TOKEN_EXPIRES_MINUTES)
    refresh_token = security.create_refresh_token(
        data={"sub": user.email},
        expires_delta=refresh_token_expires,
    )
    response.set_cookie(key="access_token",value=f"{access_token}", httponly=True)
    response.set_cookie(key="refresh_token",value=f"{refresh_token}", httponly=True)
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}

@app.get("/test-auth-endpoint")
def sample_endpoint_under_jwt(
    current_user: User = Depends(utils.get_current_user_from_token),
):
    return {"Success": True, "current_user": current_user}

