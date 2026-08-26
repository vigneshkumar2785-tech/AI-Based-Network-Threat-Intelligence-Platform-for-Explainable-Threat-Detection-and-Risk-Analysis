from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.ml.predictor import predict
from app.xai.explainer import explain

router = APIRouter(prefix="/xai", tags=["Explainable AI (XAI)"])

@router.post("/explain")
def get_xai_explanation(event: Dict[str, Any]):
    """
    Run XAI explanation (SHAP + LIME) for any raw network event payload.
    """
    try:
        prediction = predict(event)
        explanation = explain(event, prediction)
        return {
            "prediction": prediction,
            "explanation": explanation
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"XAI calculation failed: {str(e)}")
