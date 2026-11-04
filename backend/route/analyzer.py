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