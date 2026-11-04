import uvicorn

from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from functions.analyzer import AnalyzerRuntime
from route.analyzer import router as analyzer_router
from route.aiTests import router as ai_router
from route.base import router as base_router


@asynccontextmanager
async def lifespan(app):
    runtime = AnalyzerRuntime()
    app.state.analyzer = runtime
    try:
        runtime.train()
        print("Anomaly detector trained from traffic history.", flush=True)
    except ValueError as error:
        print(f"Anomaly detector not trained: {error}", flush=True)

    runtime.start_sniffing()
    yield
    runtime.stop_sniffing()


app = FastAPI(title="GuardianBees API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "FRONTEND_ORIGIN",
            "http://localhost:3000,http://localhost:5173",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(base_router)
app.include_router(analyzer_router)
app.include_router(ai_router)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
