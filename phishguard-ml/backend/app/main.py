from contextlib import asynccontextmanager
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from app.analyzers.domain_analyzer import analyze_domain
from app.analyzers.email_analyzer import analyze_email
from app.analyzers.url_analyzer import analyze_url
from app.analyzers.website_analyzer import analyze_html
from app.database import init_db, recent_analyses, save_analysis
from app.schemas import TextAnalysisRequest, UrlRequest, ValueRequest

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield

app = FastAPI(title="PhishGuard ML API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
MAX_UPLOAD = 5 * 1024 * 1024

def persist(result):
    data = result.model_dump()
    save_analysis(data)
    return data

@app.get("/api/health")
def health(): return {"status": "ok"}

@app.post("/api/analyze/url")
def url_endpoint(request: UrlRequest):
    try: return persist(analyze_url(request.url))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/analyze/email")
def email_endpoint(request: TextAnalysisRequest): return persist(analyze_email(request.subject, request.body, request.sender, request.reply_to))

@app.post("/api/analyze/eml")
async def eml_endpoint(file: UploadFile = File(...)):
    if file.content_type not in {"message/rfc822", "application/octet-stream", "text/plain"}: raise HTTPException(status_code=415, detail="Upload an .eml-compatible file")
    content = await file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD: raise HTTPException(status_code=413, detail="File exceeds the 5 MB limit")
    try: return persist(analyze_email("", "", eml_bytes=content))
    except Exception as exc: raise HTTPException(status_code=422, detail=f"Could not parse email: {exc}") from exc

@app.post("/api/analyze/html")
async def html_endpoint(file: UploadFile = File(...)):
    if file.content_type not in {"text/html", "text/plain", "application/octet-stream"}: raise HTTPException(status_code=415, detail="Upload an HTML file")
    content = await file.read(MAX_UPLOAD + 1)
    if len(content) > MAX_UPLOAD: raise HTTPException(status_code=413, detail="File exceeds the 5 MB limit")
    return persist(analyze_html(content.decode("utf-8", errors="replace")))

@app.post("/api/analyze/ip")
def ip_endpoint(request: ValueRequest):
    try:
        kind, value = __import__("app.utils.validators", fromlist=["parse_ip_or_hostname"]).parse_ip_or_hostname(request.value)
        if kind != "ip": raise ValueError("Value is not an IP address")
        return persist(analyze_domain(value, "ip"))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.post("/api/analyze/domain")
def domain_endpoint(request: ValueRequest):
    try:
        kind, value = __import__("app.utils.validators", fromlist=["parse_ip_or_hostname"]).parse_ip_or_hostname(request.value)
        if kind != "domain": raise ValueError("Value is an IP address; use the IP analyzer")
        return persist(analyze_domain(value, "domain"))
    except ValueError as exc: raise HTTPException(status_code=422, detail=str(exc)) from exc

@app.get("/api/history")
def history_endpoint(): return recent_analyses()
