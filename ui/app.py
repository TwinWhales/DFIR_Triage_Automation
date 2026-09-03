from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from ui.routes.analysis import router as analysis_router
from ui.routes.evidence import router as evidence_router
from ui.routes.results import router as results_router


BASE_DIR = Path(__file__).resolve().parent


app = FastAPI(
    title="8vidence",
    description="Evidence-driven DFIR Triage",
    version="0.1.0",
)


app.mount(
    "/static",
    StaticFiles(
        directory=BASE_DIR / "static"
    ),
    name="static",
)


templates = Jinja2Templates(
    directory=BASE_DIR / "templates"
)


app.include_router(
    analysis_router
)

app.include_router(
    evidence_router
)

app.include_router(
    results_router
)


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def index(
    request: Request,
):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={},
    )


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "app": "8vidence",
    }