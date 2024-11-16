import os
from dotenv import load_dotenv

def load_env_variables(env_file: str):
    load_dotenv(env_file)
    return {key: os.getenv(key) for key in os.environ.keys()}

def get_env_variable(var_name: str, default: str = None) -> str:
    value = os.getenv(var_name, default)
    if value is None:
        raise KeyError(f"Environment variable '{var_name}' not found and no default value provided.")
    return value

