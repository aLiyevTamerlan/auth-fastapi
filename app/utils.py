from datetime import timedelta
import hashing, settings, security
from typing import Union, Optional, Dict
from fastapi import Depends, HTTPException, Response, status, Request
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordBearer, OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from db.models import User
from db.session import get_db



def get_user_by_email(email, db: Session):
    user = db.query(User).filter(User.email == email).first()

    if user is None: return None
    return user 

class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,

        scheme_name: Optional[str] = None,
        scopes: Optional[Dict[str, str]] = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(password={"tokenUrl": tokenUrl, "scopes": scopes})

        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self,response: Response, request: Request) -> Optional[str]:
        access_token: str = request.cookies.get("access_token")
        refresh_token: str = request.cookies.get("refresh_token")

        scheme, param = get_authorization_scheme_param(f'Bearer {access_token}')   
        if not access_token or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
            
        try:
            payload = jwt.decode(
                access_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            email: str = payload.get("sub")

            if email is None:
                raise JWTError()

            return access_token

        except JWTError:

            if not refresh_token:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                else:
                    return None

            try:

                refresh_payload = jwt.decode(
                    refresh_token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
                )
                email: str = refresh_payload.get("sub")

                if email is None:
                    raise JWTError()


                new_access_token = jwt.encode(
                    {"sub": email}, settings.SECRET_KEY, algorithm=settings.ALGORITHM
                )
                
                response.set_cookie("access_token", new_access_token)

                return new_access_token

            except JWTError:
                if self.auto_error:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Not authenticated",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                else:
                    return None

        
oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="/token")



def get_current_user_from_token(token: str = Depends(oauth2_scheme), db: Session=Depends(get_db)):

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        email: str = payload.get("sub")

        if email is None:
            raise credentials_exception
        
        user = get_user_by_email(email, db)

        return user
    
    except JWTError:
        raise credentials_exception

def authenticate_user(db: Session, username: str, password: str) -> Union[User, None]:
    user = db.query(User).filter(User.email == username).first()
    
    if user is None:
        return False
    
    if not hashing.Hasher.verify_password(password, user.hashed_password):
        return False
    
    return user
