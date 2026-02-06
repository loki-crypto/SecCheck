"""
Security Checklist Application - API Routes
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update, delete
from sqlalchemy.orm import selectinload, joinedload
from typing import Optional, List
from datetime import datetime
import uuid
import os
import shutil
import json
import logging

from app.database import get_db
from app.auth import (
    get_current_user, get_current_active_user, require_admin, require_auditor_or_admin,
    verify_password, get_password_hash, create_access_token, rate_limiter
)
from app.models import (
    User, UserRole, Application, Category, Check, CheckResult, CheckStatus,
    CheckAttachment, CheckHistory, TestExecution, ActionPlan, AuditLog,
    Severity, Environment, TestResult as TestResultEnum
)
from app.schemas import (
    UserCreate, UserUpdate, UserResponse, UserLogin, Token, PasswordChange,
    ApplicationCreate, ApplicationUpdate, ApplicationResponse, ApplicationStats,
    CategoryCreate, CategoryResponse,
    CheckCreate, CheckUpdate, CheckResponse, CheckWithCategory,
    CheckResultCreate, CheckResultUpdate, CheckResultResponse, CheckResultWithDetails,
    AttachmentResponse, CheckHistoryResponse,
    TestExecutionRequest, TestExecutionResponse,
    ActionPlanCreate, ActionPlanUpdate, ActionPlanResponse,
    ReportSummary, DashboardStats
)
from app.test_executor import SecurityTestExecutor, TestType
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Create routers
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
users_router = APIRouter(prefix="/api/users", tags=["Users"])
applications_router = APIRouter(prefix="/api/applications", tags=["Applications"])
categories_router = APIRouter(prefix="/api/categories", tags=["Categories"])
checks_router = APIRouter(prefix="/api/checks", tags=["Checks"])
results_router = APIRouter(prefix="/api/results", tags=["Check Results"])
tests_router = APIRouter(prefix="/api/tests", tags=["Test Execution"])
reports_router = APIRouter(prefix="/api/reports", tags=["Reports"])
dashboard_router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

# ============== AUTHENTICATION ==============

@auth_router.post("/login", response_model=Token)
async def login(
    request: Request,
    credentials: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """Login and get access token"""
    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    if not rate_limiter.is_allowed(f"login:{client_ip}", max_requests=10, window_seconds=60):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later."
        )
    
    result = await db.execute(select(User).where(User.username == credentials.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(credentials.password, user.password_hash):
        # Log failed attempt
        await db.execute(
            AuditLog.__table__.insert().values(
                action="login_failed",
                details={"username": credentials.username},
                ip_address=client_ip,
                created_at=datetime.utcnow()
            )
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is disabled"
        )
    
    # Update last login
    user.last_login = datetime.utcnow()
    
    # Create token
    token = create_access_token(data={"sub": user.username, "role": user.role.value})
    
    # Log successful login
    await db.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="login_success",
            ip_address=client_ip,
            created_at=datetime.utcnow()
        )
    )
    
    response = Token(
        access_token=token,
        user=UserResponse.model_validate(user)
    )
    
    return response


@auth_router.post("/logout")
async def logout(
    response: Response,
    current_user: User = Depends(get_current_active_user)
):
    """Logout current user"""
    response.delete_cookie("access_token")
    return {"message": "Logged out successfully"}


@auth_router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user information"""
    return UserResponse.model_validate(current_user)


@auth_router.post("/change-password")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Change current user's password"""
    if not verify_password(password_data.current_password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    current_user.password_hash = get_password_hash(password_data.new_password)
    return {"message": "Password changed successfully"}


# ============== USERS ==============

@users_router.get("", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """List all users (admin only)"""
    result = await db.execute(select(User).order_by(User.username))
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@users_router.post("", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Create a new user (admin only)"""
    # Check if username exists
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Check if email exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists"
        )
    
    user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=get_password_hash(user_data.password),
        role=user_data.role
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    
    return UserResponse.model_validate(user)


@users_router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    user_data: UserUpdate,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update a user (admin only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user_data.email:
        user.email = user_data.email
    if user_data.role:
        user.role = user_data.role
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    
    return UserResponse.model_validate(user)


@users_router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete a user (admin only)"""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await db.delete(user)
    return {"message": "User deleted successfully"}


# ============== APPLICATIONS ==============

@applications_router.get("", response_model=List[ApplicationResponse])
async def list_applications(
    search: Optional[str] = None,
    environment: Optional[Environment] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all applications"""
    query = select(Application).where(Application.is_active == True)
    
    if search:
        query = query.where(
            or_(
                Application.name.ilike(f"%{search}%"),
                Application.description.ilike(f"%{search}%"),
                Application.tags.ilike(f"%{search}%")
            )
        )
    
    if environment:
        query = query.where(Application.environment == environment)
    
    query = query.order_by(Application.name)
    result = await db.execute(query)
    apps = result.scalars().all()
    
    return [ApplicationResponse.model_validate(app) for app in apps]


@applications_router.get("/{app_id}", response_model=ApplicationResponse)
async def get_application(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get application by ID"""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    return ApplicationResponse.model_validate(app)


@applications_router.get("/{app_id}/stats", response_model=ApplicationStats)
async def get_application_stats(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get application statistics"""
    # Verify app exists
    result = await db.execute(select(Application).where(Application.id == app_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")
    
    # Count checks
    total_checks = await db.execute(select(func.count(Check.id)).where(Check.is_active == True))
    total_checks = total_checks.scalar()
    
    # Get results for this app
    results_query = select(CheckResult).where(CheckResult.application_id == app_id)
    results = await db.execute(results_query)
    results = results.scalars().all()
    
    status_counts = {
        CheckStatus.APPROVED: 0,
        CheckStatus.FAILED: 0,
        CheckStatus.IN_PROGRESS: 0,
        CheckStatus.NOT_STARTED: 0,
        CheckStatus.NOT_APPLICABLE: 0
    }
    
    for r in results:
        if r.status in status_counts:
            status_counts[r.status] += 1
    
    # Calculate checks without results as NOT_STARTED
    checks_with_results = len(results)
    status_counts[CheckStatus.NOT_STARTED] = max(0, total_checks - checks_with_results + status_counts[CheckStatus.NOT_STARTED])
    
    # Get critical/high issues
    critical_query = select(func.count(CheckResult.id)).join(Check).where(
        and_(
            CheckResult.application_id == app_id,
            CheckResult.status == CheckStatus.FAILED,
            Check.severity == Severity.CRITICAL
        )
    )
    critical = await db.execute(critical_query)
    critical_issues = critical.scalar() or 0
    
    high_query = select(func.count(CheckResult.id)).join(Check).where(
        and_(
            CheckResult.application_id == app_id,
            CheckResult.status == CheckStatus.FAILED,
            Check.severity == Severity.HIGH
        )
    )
    high = await db.execute(high_query)
    high_issues = high.scalar() or 0
    
    # Calculate completion
    applicable_checks = total_checks - status_counts[CheckStatus.NOT_APPLICABLE]
    completed_checks = status_counts[CheckStatus.APPROVED] + status_counts[CheckStatus.FAILED]
    completion = (completed_checks / applicable_checks * 100) if applicable_checks > 0 else 0
    
    return ApplicationStats(
        total_checks=total_checks,
        approved=status_counts[CheckStatus.APPROVED],
        failed=status_counts[CheckStatus.FAILED],
        in_progress=status_counts[CheckStatus.IN_PROGRESS],
        not_started=status_counts[CheckStatus.NOT_STARTED],
        not_applicable=status_counts[CheckStatus.NOT_APPLICABLE],
        completion_percentage=round(completion, 1),
        critical_issues=critical_issues,
        high_issues=high_issues
    )


@applications_router.post("", response_model=ApplicationResponse)
async def create_application(
    app_data: ApplicationCreate,
    current_user: User = Depends(require_auditor_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """Create a new application"""
    app = Application(**app_data.model_dump())
    db.add(app)
    await db.flush()
    await db.refresh(app)
    
    # Log
    db.add(AuditLog(
        user_id=current_user.id,
        action="create_application",
        entity_type="application",
        entity_id=app.id,
        details={"name": app.name}
    ))
    
    return ApplicationResponse.model_validate(app)


@applications_router.put("/{app_id}", response_model=ApplicationResponse)
async def update_application(
    app_id: int,
    app_data: ApplicationUpdate,
    current_user: User = Depends(require_auditor_or_admin),
    db: AsyncSession = Depends(get_db)
):
    """Update an application"""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    update_data = app_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(app, key, value)
    
    app.updated_at = datetime.utcnow()
    
    return ApplicationResponse.model_validate(app)


@applications_router.delete("/{app_id}")
async def delete_application(
    app_id: int,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db)
):
    """Delete an application"""
    result = await db.execute(select(Application).where(Application.id == app_id))
    app = result.scalar_one_or_none()
    
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    await db.delete(app)
    return {"message": "Application deleted successfully"}


# ============== CATEGORIES ==============

@categories_router.get("", response_model=List[CategoryResponse])
async def list_categories(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all categories with check counts"""
    query = select(Category).order_by(Category.order)
    result = await db.execute(query)
    categories = result.scalars().all()
    
    response = []
    for cat in categories:
        # Count checks
        count_query = select(func.count(Check.id)).where(
            and_(Check.category_id == cat.id, Check.is_active == True)
        )
        count_result = await db.execute(count_query)
        checks_count = count_result.scalar()
        
        cat_response = CategoryResponse.model_validate(cat)
        cat_response.checks_count = checks_count
        response.append(cat_response)
    
    return response


@categories_router.get("/{category_id}", response_model=CategoryResponse)
async def get_category(
    category_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get category by ID"""
    result = await db.execute(select(Category).where(Category.id == category_id))
    category = result.scalar_one_or_none()
    
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    
    return CategoryResponse.model_validate(category)


# ============== CHECKS ==============

@checks_router.get("", response_model=List[CheckWithCategory])
async def list_checks(
    category_id: Optional[int] = None,
    severity: Optional[Severity] = None,
    has_automated_test: Optional[bool] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all checks with optional filters"""
    query = select(Check).where(Check.is_active == True)
    
    if category_id:
        query = query.where(Check.category_id == category_id)
    if severity:
        query = query.where(Check.severity == severity)
    if has_automated_test is not None:
        query = query.where(Check.has_automated_test == has_automated_test)
    if search:
        query = query.where(
            or_(
                Check.code.ilike(f"%{search}%"),
                Check.title.ilike(f"%{search}%"),
                Check.description.ilike(f"%{search}%")
            )
        )
    
    query = query.order_by(Check.category_id, Check.order, Check.code)
    result = await db.execute(query)
    checks = result.scalars().all()
    
    # Get category info
    response = []
    for check in checks:
        cat_result = await db.execute(select(Category).where(Category.id == check.category_id))
        category = cat_result.scalar_one_or_none()
        
        check_data = CheckWithCategory.model_validate(check)
        if category:
            check_data.category_name = category.name
            check_data.category_code = category.code
        response.append(check_data)
    
    return response


@checks_router.get("/{check_id}", response_model=CheckWithCategory)
async def get_check(
    check_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get check by ID"""
    result = await db.execute(select(Check).where(Check.id == check_id))
    check = result.scalar_one_or_none()
    
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    
    cat_result = await db.execute(select(Category).where(Category.id == check.category_id))
    category = cat_result.scalar_one_or_none()
    
    check_data = CheckWithCategory.model_validate(check)
    if category:
        check_data.category_name = category.name
        check_data.category_code = category.code
    
    return check_data


# ============== CHECK RESULTS ==============

@results_router.get("/application/{app_id}", response_model=List[CheckResultWithDetails])
async def get_application_results(
    app_id: int,
    category_id: Optional[int] = None,
    status_filter: Optional[CheckStatus] = None,
    severity: Optional[Severity] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get all check results for an application"""
    # Verify app exists
    app_result = await db.execute(select(Application).where(Application.id == app_id))
    if not app_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")
    
    # Get all checks
    checks_query = select(Check).where(Check.is_active == True)
    if category_id:
        checks_query = checks_query.where(Check.category_id == category_id)
    if severity:
        checks_query = checks_query.where(Check.severity == severity)
    
    checks_query = checks_query.order_by(Check.category_id, Check.order, Check.code)
    checks_result = await db.execute(checks_query)
    checks = checks_result.scalars().all()
    
    response = []
    for check in checks:
        # Get result for this check
        result_query = select(CheckResult).where(
            and_(
                CheckResult.application_id == app_id,
                CheckResult.check_id == check.id
            )
        )
        result = await db.execute(result_query)
        check_result = result.scalar_one_or_none()
        
        # Apply status filter
        if status_filter:
            if check_result and check_result.status != status_filter:
                continue
            if not check_result and status_filter != CheckStatus.NOT_STARTED:
                continue
        
        # Get category
        cat_result = await db.execute(select(Category).where(Category.id == check.category_id))
        category = cat_result.scalar_one_or_none()
        
        check_with_cat = CheckWithCategory.model_validate(check)
        if category:
            check_with_cat.category_name = category.name
            check_with_cat.category_code = category.code
        
        if check_result:
            # Get attachments
            attachments_query = select(CheckAttachment).where(
                CheckAttachment.check_result_id == check_result.id
            )
            attachments_result = await db.execute(attachments_query)
            attachments = attachments_result.scalars().all()
            
            # Get last test result
            test_query = select(TestExecution).where(
                and_(
                    TestExecution.application_id == app_id,
                    TestExecution.check_id == check.id
                )
            ).order_by(TestExecution.executed_at.desc()).limit(1)
            test_result = await db.execute(test_query)
            last_test = test_result.scalar_one_or_none()
            
            result_data = CheckResultWithDetails(
                id=check_result.id,
                application_id=check_result.application_id,
                check_id=check_result.check_id,
                status=check_result.status,
                notes=check_result.notes,
                evidence=check_result.evidence,
                responsible_id=check_result.responsible_id,
                created_at=check_result.created_at,
                updated_at=check_result.updated_at,
                check=check_with_cat,
                attachments=[AttachmentResponse.model_validate(a) for a in attachments],
                last_test_result=TestExecutionResponse.model_validate(last_test) if last_test else None
            )
        else:
            result_data = CheckResultWithDetails(
                id=0,
                application_id=app_id,
                check_id=check.id,
                status=CheckStatus.NOT_STARTED,
                notes=None,
                evidence=None,
                responsible_id=None,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                check=check_with_cat,
                attachments=[],
                last_test_result=None
            )
        
        response.append(result_data)
    
    return response


@results_router.post("", response_model=CheckResultResponse)
async def create_or_update_result(
    result_data: CheckResultUpdate,
    app_id: int = Query(...),
    check_id: int = Query(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Create or update a check result"""
    # Verify app and check exist
    app_result = await db.execute(select(Application).where(Application.id == app_id))
    if not app_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Application not found")
    
    check_result = await db.execute(select(Check).where(Check.id == check_id))
    if not check_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Check not found")
    
    # Check if result exists
    existing_query = select(CheckResult).where(
        and_(
            CheckResult.application_id == app_id,
            CheckResult.check_id == check_id
        )
    )
    existing_result = await db.execute(existing_query)
    existing = existing_result.scalar_one_or_none()
    
    if existing:
        # Update existing
        old_status = existing.status
        
        update_data = result_data.model_dump(exclude_unset=True, exclude={"comment"})
        for key, value in update_data.items():
            setattr(existing, key, value)
        
        existing.responsible_id = current_user.id
        existing.updated_at = datetime.utcnow()
        
        # Add to history if status changed
        if result_data.status and old_status != result_data.status:
            history = CheckHistory(
                check_result_id=existing.id,
                user_id=current_user.id,
                old_status=old_status,
                new_status=result_data.status,
                comment=result_data.comment,
                changes=update_data
            )
            db.add(history)
        
        await db.flush()
        return CheckResultResponse.model_validate(existing)
    else:
        # Create new
        new_result = CheckResult(
            application_id=app_id,
            check_id=check_id,
            status=result_data.status or CheckStatus.NOT_STARTED,
            notes=result_data.notes,
            evidence=result_data.evidence,
            responsible_id=current_user.id
        )
        db.add(new_result)
        await db.flush()
        await db.refresh(new_result)
        
        # Add initial history
        history = CheckHistory(
            check_result_id=new_result.id,
            user_id=current_user.id,
            old_status=None,
            new_status=new_result.status,
            comment=result_data.comment
        )
        db.add(history)
        
        return CheckResultResponse.model_validate(new_result)


@results_router.get("/{result_id}/history", response_model=List[CheckHistoryResponse])
async def get_result_history(
    result_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get history for a check result"""
    query = select(CheckHistory).where(
        CheckHistory.check_result_id == result_id
    ).order_by(CheckHistory.created_at.desc())
    
    result = await db.execute(query)
    history = result.scalars().all()
    
    response = []
    for h in history:
        user_query = await db.execute(select(User).where(User.id == h.user_id))
        user = user_query.scalar_one_or_none()
        
        h_data = CheckHistoryResponse.model_validate(h)
        h_data.username = user.username if user else "Unknown"
        response.append(h_data)
    
    return response


@results_router.post("/{result_id}/attachments")
async def upload_attachment(
    result_id: int,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Upload an attachment for a check result"""
    # Verify result exists
    result = await db.execute(select(CheckResult).where(CheckResult.id == result_id))
    check_result = result.scalar_one_or_none()
    
    if not check_result:
        raise HTTPException(status_code=404, detail="Check result not found")
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    # Check extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400, 
            detail=f"File type not allowed. Allowed: {settings.ALLOWED_EXTENSIONS}"
        )
    
    # Check size
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
        raise HTTPException(
            status_code=400,
            detail=f"File too large. Max size: {settings.MAX_UPLOAD_SIZE_MB}MB"
        )
    
    # Generate safe filename
    safe_filename = f"{uuid.uuid4()}{ext}"
    filepath = os.path.join(settings.UPLOAD_FOLDER, safe_filename)
    
    # Ensure directory exists
    os.makedirs(settings.UPLOAD_FOLDER, exist_ok=True)
    
    # Save file
    with open(filepath, "wb") as f:
        f.write(content)
    
    # Create attachment record
    attachment = CheckAttachment(
        check_result_id=result_id,
        filename=safe_filename,
        original_filename=file.filename,
        filepath=filepath,
        file_size=len(content),
        mime_type=file.content_type
    )
    db.add(attachment)
    await db.flush()
    await db.refresh(attachment)
    
    return AttachmentResponse.model_validate(attachment)


@results_router.delete("/attachments/{attachment_id}")
async def delete_attachment(
    attachment_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete an attachment"""
    result = await db.execute(select(CheckAttachment).where(CheckAttachment.id == attachment_id))
    attachment = result.scalar_one_or_none()
    
    if not attachment:
        raise HTTPException(status_code=404, detail="Attachment not found")
    
    # Delete file
    if os.path.exists(attachment.filepath):
        os.remove(attachment.filepath)
    
    await db.delete(attachment)
    return {"message": "Attachment deleted"}


# ============== TEST EXECUTION ==============

@tests_router.post("/execute", response_model=TestExecutionResponse)
async def execute_test(
    request: TestExecutionRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Execute an automated security test"""
    # Verify app and check exist
    app_result = await db.execute(select(Application).where(Application.id == request.application_id))
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    check_result = await db.execute(select(Check).where(Check.id == request.check_id))
    check = check_result.scalar_one_or_none()
    if not check:
        raise HTTPException(status_code=404, detail="Check not found")
    
    if not check.has_automated_test:
        raise HTTPException(status_code=400, detail="This check does not have an automated test")
    
    # Get target URL
    target_url = request.target_url or app.base_url
    if not target_url:
        raise HTTPException(status_code=400, detail="No target URL provided")
    
    # Validate URL
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    
    # Execute test
    try:
        async with SecurityTestExecutor() as executor:
            test_config = {**(check.test_config or {}), **(request.custom_config or {})}
            result = await executor.execute_test(check.test_type, target_url, test_config)
    except Exception as e:
        logger.error(f"Test execution error: {str(e)}")
        result_enum = TestResultEnum.ERROR
        output = f"Test execution failed: {str(e)}"
        details = {"error": str(e)}
        duration = 0
    else:
        result_enum = TestResultEnum(result.result)
        output = result.message
        details = result.details
        duration = result.duration_ms
    
    # Save execution
    execution = TestExecution(
        application_id=request.application_id,
        check_id=request.check_id,
        result=result_enum,
        output=output,
        details=details,
        duration_ms=duration,
        executed_by_id=current_user.id
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    
    return TestExecutionResponse.model_validate(execution)


@tests_router.get("/application/{app_id}", response_model=List[TestExecutionResponse])
async def get_application_tests(
    app_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get test executions for an application"""
    query = select(TestExecution).where(
        TestExecution.application_id == app_id
    ).order_by(TestExecution.executed_at.desc()).limit(limit)
    
    result = await db.execute(query)
    executions = result.scalars().all()
    
    return [TestExecutionResponse.model_validate(e) for e in executions]


@tests_router.get("/recent", response_model=List[TestExecutionResponse])
async def get_recent_tests(
    limit: int = 10,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get recent test executions across all applications"""
    query = select(TestExecution).order_by(
        TestExecution.executed_at.desc()
    ).limit(limit)
    
    result = await db.execute(query)
    executions = result.scalars().all()
    
    return [TestExecutionResponse.model_validate(e) for e in executions]


@tests_router.get("/{execution_id}", response_model=TestExecutionResponse)
async def get_test_execution(
    execution_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get a specific test execution by ID"""
    result = await db.execute(
        select(TestExecution).where(TestExecution.id == execution_id)
    )
    execution = result.scalar_one_or_none()
    
    if not execution:
        raise HTTPException(status_code=404, detail="Test execution not found")
    
    return TestExecutionResponse.model_validate(execution)


# ============== REPORTS ==============

@reports_router.get("/summary/{app_id}", response_model=ReportSummary)
@reports_router.get("/application/{app_id}/summary", response_model=ReportSummary)
async def get_report_summary(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get report summary for an application"""
    # Get application
    app_result = await db.execute(select(Application).where(Application.id == app_id))
    app = app_result.scalar_one_or_none()
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    # Get stats
    stats = await get_application_stats(app_id, current_user, db)
    
    # Get results by severity
    by_severity = {}
    for sev in Severity:
        query = select(func.count(CheckResult.id)).join(Check).where(
            and_(
                CheckResult.application_id == app_id,
                CheckResult.status == CheckStatus.FAILED,
                Check.severity == sev
            )
        )
        result = await db.execute(query)
        by_severity[sev.value] = result.scalar() or 0
    
    # Get results by category
    by_category = {}
    categories = await db.execute(select(Category).order_by(Category.order))
    for cat in categories.scalars().all():
        # Total in category
        total_query = select(func.count(Check.id)).where(
            and_(Check.category_id == cat.id, Check.is_active == True)
        )
        total = await db.execute(total_query)
        
        # Completed in category
        completed_query = select(func.count(CheckResult.id)).join(Check).where(
            and_(
                CheckResult.application_id == app_id,
                Check.category_id == cat.id,
                CheckResult.status.in_([CheckStatus.APPROVED, CheckStatus.FAILED])
            )
        )
        completed = await db.execute(completed_query)
        
        by_category[cat.name] = {
            "total": total.scalar() or 0,
            "completed": completed.scalar() or 0
        }
    
    # Get failed checks with details
    failed_results = await get_application_results(
        app_id=app_id,
        status_filter=CheckStatus.FAILED,
        current_user=current_user,
        db=db
    )
    
    # Get action plans
    plans_query = select(ActionPlan).where(
        ActionPlan.application_id == app_id
    ).order_by(ActionPlan.priority.desc(), ActionPlan.created_at.desc())
    plans_result = await db.execute(plans_query)
    action_plans = [ActionPlanResponse.model_validate(p) for p in plans_result.scalars().all()]
    
    return ReportSummary(
        application=ApplicationResponse.model_validate(app),
        stats=stats,
        by_severity=by_severity,
        by_category=by_category,
        failed_checks=failed_results,
        action_plans=action_plans,
        generated_at=datetime.utcnow()
    )


# ============== ACTION PLANS ==============

@reports_router.get("/application/{app_id}/actions", response_model=List[ActionPlanResponse])
async def get_action_plans(
    app_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get action plans for an application"""
    query = select(ActionPlan).where(
        ActionPlan.application_id == app_id
    ).order_by(ActionPlan.priority.desc(), ActionPlan.due_date)
    
    result = await db.execute(query)
    plans = result.scalars().all()
    
    return [ActionPlanResponse.model_validate(p) for p in plans]


@reports_router.post("/application/{app_id}/actions", response_model=ActionPlanResponse)
async def create_action_plan(
    app_id: int,
    plan_data: ActionPlanCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Create an action plan"""
    plan = ActionPlan(
        application_id=app_id,
        check_id=plan_data.check_id,
        task=plan_data.task,
        priority=plan_data.priority,
        status=plan_data.status,
        due_date=plan_data.due_date,
        assigned_to=plan_data.assigned_to,
        notes=plan_data.notes
    )
    db.add(plan)
    await db.flush()
    await db.refresh(plan)
    
    return ActionPlanResponse.model_validate(plan)


@reports_router.put("/actions/{plan_id}", response_model=ActionPlanResponse)
async def update_action_plan(
    plan_id: int,
    plan_data: ActionPlanUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Update an action plan"""
    result = await db.execute(select(ActionPlan).where(ActionPlan.id == plan_id))
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="Action plan not found")
    
    update_data = plan_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(plan, key, value)
    
    plan.updated_at = datetime.utcnow()
    
    return ActionPlanResponse.model_validate(plan)


@reports_router.delete("/actions/{plan_id}")
async def delete_action_plan(
    plan_id: int,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete an action plan"""
    result = await db.execute(select(ActionPlan).where(ActionPlan.id == plan_id))
    plan = result.scalar_one_or_none()
    
    if not plan:
        raise HTTPException(status_code=404, detail="Action plan not found")
    
    await db.delete(plan)
    return {"message": "Action plan deleted"}


# ============== DASHBOARD ==============

@dashboard_router.get("/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get dashboard statistics"""
    # Total applications
    apps_count = await db.execute(
        select(func.count(Application.id)).where(Application.is_active == True)
    )
    total_apps = apps_count.scalar() or 0
    
    # Total checks
    checks_count = await db.execute(
        select(func.count(Check.id)).where(Check.is_active == True)
    )
    total_checks = checks_count.scalar() or 0
    
    # Overall compliance
    total_results = await db.execute(select(func.count(CheckResult.id)))
    approved_results = await db.execute(
        select(func.count(CheckResult.id)).where(CheckResult.status == CheckStatus.APPROVED)
    )
    total = total_results.scalar() or 0
    approved = approved_results.scalar() or 0
    overall_compliance = (approved / total * 100) if total > 0 else 0
    
    # Critical/High findings
    critical_query = select(func.count(CheckResult.id)).join(Check).where(
        and_(
            CheckResult.status == CheckStatus.FAILED,
            Check.severity == Severity.CRITICAL
        )
    )
    critical = await db.execute(critical_query)
    critical_findings = critical.scalar() or 0
    
    high_query = select(func.count(CheckResult.id)).join(Check).where(
        and_(
            CheckResult.status == CheckStatus.FAILED,
            Check.severity == Severity.HIGH
        )
    )
    high = await db.execute(high_query)
    high_findings = high.scalar() or 0
    
    # Recent tests
    tests_query = select(TestExecution).order_by(
        TestExecution.executed_at.desc()
    ).limit(10)
    tests_result = await db.execute(tests_query)
    recent_tests = [TestExecutionResponse.model_validate(t) for t in tests_result.scalars().all()]
    
    # Applications summary
    apps_query = select(Application).where(Application.is_active == True).limit(10)
    apps_result = await db.execute(apps_query)
    
    apps_summary = []
    for app in apps_result.scalars().all():
        stats = await get_application_stats(app.id, current_user, db)
        apps_summary.append({
            "id": app.id,
            "name": app.name,
            "environment": app.environment.value,
            "completion": stats.completion_percentage,
            "critical_issues": stats.critical_issues,
            "high_issues": stats.high_issues
        })
    
    return DashboardStats(
        total_applications=total_apps,
        total_checks=total_checks,
        overall_compliance=round(overall_compliance, 1),
        critical_findings=critical_findings,
        high_findings=high_findings,
        recent_tests=recent_tests,
        applications_summary=apps_summary
    )


# ============== MAIN ROUTER ==============
# Include all sub-routers into the main router (must be at the end after all routes are defined)
router = APIRouter()
router.include_router(auth_router)
router.include_router(users_router)
router.include_router(applications_router)
router.include_router(categories_router)
router.include_router(checks_router)
router.include_router(results_router)
router.include_router(tests_router)
router.include_router(reports_router)
router.include_router(dashboard_router)
