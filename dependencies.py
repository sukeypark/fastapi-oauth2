from typing import Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from fastapi.security.utils import get_authorization_scheme_param
from pydantic_settings import SettingsConfigDict
import requests
from jose import jwt

from config import settings


class CustomOAuth2AuthorizationCodeBearer(OAuth2AuthorizationCodeBearer):
    async def __call__(self, request: Request) -> Optional[str]:
        authorization = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None
        return param


reusable_oauth2 = CustomOAuth2AuthorizationCodeBearer(
    authorizationUrl=settings.OAUTH2_AUTHORIZATION_ENDPOINT,
    tokenUrl=settings.OAUTH2_TOKEN_ENDPOINT,
    refreshUrl=settings.OAUTH2_TOKEN_ENDPOINT,
)


def parse_jwt_token(token: str = Depends(reusable_oauth2)):
    resp = requests.get(
        f"{settings.OAUTH2_HOST}/security/publickey", headers={"Authorization": token}
    )
    if resp.status_code != status.HTTP_200_OK:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    pub_key = resp.json()["publickey"]
    algorithm = jwt.get_unverified_header(token).get("alg")
    audience = jwt.get_unverified_claims(token).get("aud")
    return jwt.decode(token, pub_key, audience=audience, algorithms=[algorithm])


def get_current_user(token_info=Depends(parse_jwt_token)):
    return {
        "user_id": token_info["userId"],
        "nickname": token_info["nickname"],
        "email": token_info["email"],
        "role": token_info["role"],
    }
