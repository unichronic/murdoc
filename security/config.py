import os
from dotenv import load_dotenv
load_dotenv()
LAKERA_API_KEY = os.getenv("LAKERA_API_KEY", "")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))
