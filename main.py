"""
Security Checklist - DevSecOps Web Application
Main entry point
"""

import os
import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Add app directory to path
sys.path.insert(0, str(Path(__file__).parent))

from app.config import settings
from app.database import engine, async_session, Base
from app.routes import router as api_router
from app.auth import get_current_user_optional
from app.seed_data import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("🚀 Starting Security Checklist Application...")
    
    # Create database tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✅ Database tables created")
    
    # Seed initial data
    async with async_session() as session:
        await seed_database(session)
    print("✅ Database seeded with initial data")
    
    # Create upload directory
    upload_dir = Path(settings.UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    print(f"✅ Upload directory ready: {upload_dir}")
    
    print("=" * 50)
    print(f"🔐 Security Checklist running on http://localhost:{settings.PORT}")
    print("=" * 50)
    
    yield
    
    # Shutdown
    print("👋 Shutting down...")
    await engine.dispose()


# Create FastAPI application
# Desabilitando documentação para não expor endpoints
app = FastAPI(
    title="Security Checklist",
    description="DevSecOps Web Application for Security Requirements Checklist",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,        # Desabilita /docs
    redoc_url=None,       # Desabilita /redoc
    openapi_url=None      # Desabilita /openapi.json
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
static_path = Path(__file__).parent / "app" / "static"
static_path.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Templates
templates_path = Path(__file__).parent / "app" / "templates"
templates = Jinja2Templates(directory=str(templates_path))

# Include API routes
app.include_router(api_router)


# ============ Page Routes ============

@app.get("/", response_class=HTMLResponse)
async def index(request: Request, user=Depends(get_current_user_optional)):
    """Dashboard page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, user=Depends(get_current_user_optional)):
    """Login page"""
    if user:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/applications", response_class=HTMLResponse)
async def applications_page(request: Request, user=Depends(get_current_user_optional)):
    """Applications management page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("applications.html", {"request": request, "user": user})


@app.get("/checklist", response_class=HTMLResponse)
async def checklist_page(request: Request, user=Depends(get_current_user_optional)):
    """Checklist page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("checklist.html", {"request": request, "user": user})


@app.get("/tests", response_class=HTMLResponse)
async def tests_page(request: Request, user=Depends(get_current_user_optional)):
    """Automated tests page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("tests.html", {"request": request, "user": user})


@app.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, user=Depends(get_current_user_optional)):
    """Reports page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("reports.html", {"request": request, "user": user})


@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, user=Depends(get_current_user_optional)):
    """User management page (admin only)"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return templates.TemplateResponse("users.html", {"request": request, "user": user})


@app.get("/categories", response_class=HTMLResponse)
async def categories_page(request: Request, user=Depends(get_current_user_optional)):
    """Categories page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("categories.html", {"request": request, "user": user})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user=Depends(get_current_user_optional)):
    """User settings page"""
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse("settings.html", {"request": request, "user": user, "active_page": "settings"})


@app.get("/logout")
async def logout(request: Request):
    """Logout and redirect to login page"""
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie("access_token")
    return response


# ============ Error Handlers ============

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Handle 404 errors"""
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=404, content={"detail": "Not found"})
    return templates.TemplateResponse(
        "base.html", 
        {"request": request, "error": "Página não encontrada"},
        status_code=404
    )


@app.exception_handler(500)
async def server_error_handler(request: Request, exc):
    """Handle 500 errors"""
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
    return templates.TemplateResponse(
        "base.html",
        {"request": request, "error": "Erro interno do servidor"},
        status_code=500
    )


# ============ Health Check ============

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "version": "1.0.0"}


# ============ Run Application ============

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
