from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="Medus")
app.mount("/", StaticFiles(directory="src/static", html=True))