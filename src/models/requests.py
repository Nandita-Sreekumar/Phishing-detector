from pydantic import BaseModel, EmailStr, Field


class EmailAnalysisRequest(BaseModel):
    """Request for email analysis."""
    raw_email: str | None = None
    email_body: str | None = None
    email_headers: dict[str, str] | None = None

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "raw_email": "From: sender@example.com\\nSubject: Test\\n\\nEmail body"
                }
            ]
        }
    }


class URLAnalysisRequest(BaseModel):
    """Request for URL analysis."""
    url: str = Field(..., min_length=1)

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "url": "<https://example.com/suspicious-link>"
                }
            ]
        }
    }