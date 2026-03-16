from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://vsapp:vspassword123@localhost:27017/vulnsamurai"
    jwt_secret: str = "changeme"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()
