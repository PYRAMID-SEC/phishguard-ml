from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator

RiskLevel = Literal["low", "medium", "high"]

class TextAnalysisRequest(BaseModel):
    subject: str = Field(default="", max_length=500)
    body: str = Field(min_length=1, max_length=200_000)
    sender: str = Field(default="", max_length=320)
    reply_to: str = Field(default="", max_length=320)

class ValueRequest(BaseModel):
    value: str = Field(min_length=1, max_length=2_048)

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Value cannot be empty")
        return value

class UrlRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4_096)

class Finding(BaseModel):
    severity: Literal["low", "medium", "high"]
    title: str
    description: str

class AnalysisResult(BaseModel):
    risk_level: RiskLevel
    probability: float = Field(ge=0, le=1)
    category: str
    model: str
    findings: list[Finding]
    features: dict[str, Any]
    recommendations: list[str]
    timestamp: str
    input_type: str
    input_label: str
