from fastapi import APIRouter, HTTPException, Request

router = APIRouter(prefix="/analyzer", tags=["analyzer"])


@router.post("/train")
def train_model(request: Request):
    """Train the anomaly detector with the retained traffic history."""
    try:
        training_records = request.app.state.analyzer.train()
    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error),
        ) from error
    return {
        "status": "trained",
        "training_records": training_records,
        "model_path": request.app.state.analyzer.model_path,
    }


@router.get("/status")
def training_status(request: Request):
    trained, training_records, model_path = request.app.state.analyzer.status()
    return {
        "trained": trained,
        "training_records": training_records,
        "model_path": model_path,
    }


@router.get("/window")
def latest_window(request: Request):
    """Return the latest 30-second traffic window grouped by source IP."""
    return request.app.state.analyzer.latest_window()


@router.get("/alerts")
def active_alerts(request: Request):
    """Return all unresolved alerts."""
    return {"alerts": request.app.state.analyzer.active_alerts()}


@router.post("/alerts/{source_ip}/resolve")
def resolve_active_alert(source_ip: str, request: Request):
    """Resolve an alert so the source IP may be analyzed again."""
    resolved = request.app.state.analyzer.resolve_alert(source_ip)
    if resolved is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"status": "resolved", "source_ip": source_ip}