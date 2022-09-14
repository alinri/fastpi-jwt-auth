from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext

import config

from jose import JWTError, jwt

from pydantic import BaseModel


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

router = APIRouter(prefix="/auth", tags=["auth"])

SIGN_ALGORITHM = "HS256"


class Token(BaseModel):
    access_token: str
    token_type: str


def verify_password(
    plain_password: str,
    hashed_passwrod: str,
) -> bool:
    return pwd_context.verify(
        plain_password,
        hashed_passwrod,
    )


def authenticate_user(
    username: str,
    password: str,
):
    if config.USERNAME == username and verify_password(
        password,
        config.PASSWORD,
    ):
        return username
    return False


def create_access_token(
    data: dict,
    expires_delta: timedelta,
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update(
        {
            "exp": expire,
        },
    )
    return jwt.encode(
        to_encode,
        config.JWT_SECRET_KEY,
        SIGN_ALGORITHM,
    )


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            config.JWT_SECRET_KEY,
            SIGN_ALGORITHM,
        )
        sub = payload.get("sub")
    except JWTError:
        raise credentials_exception
    return sub


@router.post("/token/", response_model=Token)
def login_for_token(form_data: OAuth2PasswordRequestForm = Depends()):
    if not authenticate_user(
        form_data.username,
        form_data.password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wrong username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        {
            "sub": form_data.username,
            "iat": int(datetime.utcnow().timestamp()),
        },
        timedelta(minutes=config.JWT_EXPIRES_IN_MINUTES),
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@router.get("/users/me/")
def get_current_user(current_user: str = Depends(get_current_user)):
    return {"current_user": current_user}
