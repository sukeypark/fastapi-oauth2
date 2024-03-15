from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
import requests
import base64

from config import settings
from dependencies import get_current_user, parse_jwt_token, reusable_oauth2


router = APIRouter()


class OAuthCodeExchangeParams(BaseModel):
    grant_type: str = "authorization_code"
    code: str
    redirect_uri: str
    state: str


class User(BaseModel):
    user_id: str
    nickname: str
    email: str
    role: str


# TODO: token refresh / revoke / dhub data service broker에서 entity 가져오기


@router.post("/token")
def exchange_code_to_access_token(response: Response, params: OAuthCodeExchangeParams):
    headers = {"Content-type": "application/x-www-form-urlencoded"}
    resp = requests.post(
        settings.OAUTH2_TOKEN_ENDPOINT,
        headers=headers,
        data=params.model_dump(),
        auth=(settings.OAUTH2_CLIENT_ID, settings.OAUTH2_CLIENT_SECRET),
    )
    if resp.status_code != status.HTTP_200_OK:
        raise HTTPException("Auth Error")
    resp_json = resp.json()
    response.set_cookie(key="refresh_token", value=resp_json["refresh_token"])
    return resp_json


@router.get("/tokeninfo")
def token_info(token_info=Depends(parse_jwt_token)):
    return token_info


@router.get("/user/me", response_model=User)
def get_my_info(current_user=Depends(get_current_user)):
    return current_user


@router.get("/datamodels")
def read_datamodels(
    token: str = Depends(reusable_oauth2), current_user=Depends(get_current_user)
):
    resp = requests.get(
        f"{settings.DHUB_DATA_MANAGER_HOST}/datamodels",
        headers={"Authorization": token},
    )
    if resp.status_code != status.HTTP_200_OK:
        raise HTTPException(status_code=resp.status_code, detail=resp.json())
    return resp.json()
