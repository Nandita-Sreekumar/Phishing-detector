import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware

from src.analyzers.email_analyzer import EmailAnalyzer
from src.analyzers.image_analyzer import ImageAnalyzer
from src.analyzers.nlp_analyzers import NLPAnalyzer
from src.analyzers.url_analyzer import URLAnalyzer
from src.config import settings
from src.data.database import (
    get_dashboard_stats,
    get_recent_scans,
    init_database,
    save_scan_result,
)
from src.engine.scoring import ThreatScoringEngine
from src.models.requests import EmailAnalysisRequest, URLAnalysisRequest
from src.models.responses import DashboardStats, ThreatAssessment
from src.utils.email_parsers import parse_raw_email

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger.info("Starting PhishDetect AI...")
    await init_database()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down PhishDeect AI...")


# Create FastAPI app
app = FastAPI(
    title=settings.api_title,
    version=settings.api_version,
    description=settings.api_description,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzers
email_analyzer = EmailAnalyzer()
nlp_analyzer = NLPAnalyzer()
url_analyzer = URLAnalyzer()
image_analyzer = ImageAnalyzer()
scoring_engine = ThreatScoringEngine()


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": settings.api_version,
        "service": "PhishDetect AI"
    }


@app.post("/api/v1/analyze/email", response_model=ThreatAssessment)
async def analyze_email(request: EmailAnalysisRequest):
    """Analyze email for phishing indicators."""

    # Parse email
    if request.raw_email:
        parsed = parse_raw_email(request.raw_email)
        email_body = parsed["body"]
        headers = parsed["headers"]
    else:
        email_body = request.email_body or ""
        headers = request.email_headers or {}

    # Perform analysis
    header_analysis = await email_analyzer.analyze_headers(headers)
    content_analysis = await nlp_analyzer.analyze_content(email_body)
    link_analysis = await email_analyzer.analyze_links(email_body)

    # Compute threat score
    assessment = scoring_engine.compute_email_threat_score(
        header_analysis,
        content_analysis,
        link_analysis
    )

    # Save to database
    await save_scan_result(assessment.model_dump())

    return assessment


@app.post("/api/v1/analyze/url", response_model=ThreatAssessment)
async def analyze_url(request: URLAnalysisRequest):
    """Analyze URL for phishing indicators."""

    # Perform URL analysis
    url_analysis = await url_analyzer.analyze_url(request.url)

    # Compute threat score
    assessment = scoring_engine.compute_url_threat_score(url_analysis)

    # Save to database
    await save_scan_result(assessment.model_dump())

    return assessment


@app.post("/api/v1/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    """Analyze image for AI-generation indicators."""

    # Read image bytes
    image_bytes = await file.read()

    # Perform image analysis
    analysis = await image_analyzer.analyze_image(image_bytes)

    return analysis


@app.get("/api/v1/threat-feed")
async def get_threat_feed(limit: int = 50):
    """Get recent analysis results."""
    return await get_recent_scans(limit)


@app.get("/api/v1/stats", response_model=DashboardStats)
async def get_stats():
    """Get dashboard statistics."""
    stats = await get_dashboard_stats()
    return DashboardStats(**stats)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "src.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )