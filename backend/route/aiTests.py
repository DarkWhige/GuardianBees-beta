from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from functions.AI.MetaAI import MetaAIClient
from functions.normalBehaviors import (
    add_normal_behavior,
    list_normal_behaviors,
)


router = APIRouter(prefix="/ai", tags=["ai"])
client = MetaAIClient()


class AITestRequest(BaseModel):
    """Aggregated network metrics sent to Meta AI for a manual test."""

    model_config = {"extra": "forbid"}

    question: str = (
        "Analyse directement cette fenêtre de trafic agrégée, déjà signalée "
        "comme anomalie. Sois concrète et concise."
    )
    src_ip: str = "192.168.1.50"
    window_start: str = "2026-11-03T22:00:00Z"
    score: float = Field(default=1.5, ge=0)
    requests: int = Field(default=120, ge=0)
    n_ports: int = Field(default=18, ge=0)
    n_dst: int = Field(default=12, ge=0)
    n_proto: int = Field(default=2, ge=0)
    bytes: int = Field(default=250000, ge=0)
    syn_requests: int = Field(default=80, ge=0)
    outgoing_requests: int = Field(default=120, ge=0)
    local_requests: int = Field(default=0, ge=0)
    n_dns_queries: int = Field(default=35, ge=0)
    dns_queries: str = "example.com, suspicious.test"


@router.post("/test")
def test_meta_ai(payload: AITestRequest):
    """Call Meta AI with one safe, aggregated traffic example."""
    received = payload.model_dump()
    received.pop("question")
    result = client.analyze(received)
    if result is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Meta AI did not return a result. Check META_API_KEY, "
                "the API endpoint, the daily limit, and the container logs."
            ),
        )
    return {
        "status": "ok",
        "model": client.model,
        "analysis": result,
    }


@router.post("/normal-behaviors")
def mark_normal_behavior(payload: AITestRequest):
    """Mark one behavior as normal so matching alerts skip Meta."""
    behavior = payload.model_dump()
    behavior.pop("question")
    return {
        "status": "saved",
        "behavior": add_normal_behavior(behavior),
    }


@router.get("/normal-behaviors")
def get_normal_behaviors():
    """List behaviors excluded from Meta analysis."""
    return {"behaviors": list_normal_behaviors()}