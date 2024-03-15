from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        case_sensitive=True, env_file=(".env", ".env_local"), extra="ignore"
    )

    OAUTH2_CLIENT_ID: str
    OAUTH2_CLIENT_SECRET: str
    OAUTH2_HOST: str
    OAUTH2_TOKEN_ENDPOINT: str
    OAUTH2_TOKEN_REVOKE_ENDPOINT: str
    OAUTH2_AUTHORIZATION_ENDPOINT: str
    DHUB_DATA_MANAGER_HOST: str


settings = Settings()
