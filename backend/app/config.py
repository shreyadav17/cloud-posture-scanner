import os
from dotenv import load_dotenv

load_dotenv()

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() == "true"
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
DYNAMODB_TABLE = os.getenv("DYNAMODB_TABLE", "cloud-posture-scans")
CORS_ORIGINS = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",") if x.strip()]
