from fastapi import FastAPI
from fastapi.security import HTTPBasic


app = FastAPI()
security = HTTPBasic()
