# SPDX-License-Identifier: MIT
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    secret_key: str = os.getenv("SECRET_KEY", "change-me-in-.env")
    token_expire_minutes: int = int(os.getenv("TOKEN_EXPIRE_MINUTES", "480"))
    data_dir: str = os.getenv("DATA_DIR", "./data")
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")


settings = Settings()
