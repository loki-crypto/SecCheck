"""
Security Checklist Application - Pydantic Schemas
"""
from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List, Any
from datetime import datetime
from app.models import UserRole, CheckStatus, Severity, Environment, TestResult
import re


# ============== USER SCHEMAS ==============

class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole = UserRole.DEV


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    
    @field_validator('password')
    @classmethod
    def password_strength(cls, v):
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)


# ============== APPLICATION SCHEMAS ==============

class ApplicationBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    environment: Environment = Environment.DEV
    base_url: Optional[str] = None
    tags: Optional[str] = None
    responsible: Optional[str] = None
    scope_urls: Optional[str] = None
    scope_endpoints: Optional[str] = None
    scope_credentials_hint: Optional[str] = None
    scope_notes: Optional[str] = None


class ApplicationCreate(ApplicationBase):
    pass


class ApplicationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    environment: Optional[Environment] = None
    base_url: Optional[str] = None
    tags: Optional[str] = None
    responsible: Optional[str] = None
    scope_urls: Optional[str] = None
    scope_endpoints: Optional[str] = None
    scope_credentials_hint: Optional[str] = None
    scope_notes: Optional[str] = None
    is_active: Optional[bool] = None


class ApplicationResponse(ApplicationBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ApplicationStats(BaseModel):
    total_checks: int
    approved: int
    failed: int
    in_progress: int
    not_started: int
    not_applicable: int
    completion_percentage: float
    critical_issues: int
    high_issues: int


# ============== CATEGORY SCHEMAS ==============

class CategoryBase(BaseModel):
    code: str = Field(..., min_length=1, max_length=10)
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    order: int = 0
    icon: Optional[str] = None


class CategoryCreate(CategoryBase):
    pass


class CategoryResponse(CategoryBase):
    id: int
    checks_count: Optional[int] = None
    
    class Config:
        from_attributes = True


# ============== CHECK SCHEMAS ==============

class CheckBase(BaseModel):
    code: str = Field(..., min_length=1, max_length=20)
    title: str = Field(..., min_length=1, max_length=200)
    description: str
    severity: Severity = Severity.MEDIUM
    how_to_validate: Optional[str] = None
    expected_evidence: Optional[str] = None
    recommendations: Optional[str] = None
    mapping_owasp_asvs: Optional[str] = None
    mapping_owasp_top10: Optional[str] = None
    mapping_cwe: Optional[str] = None
    has_automated_test: bool = False
    test_type: Optional[str] = None
    test_config: Optional[dict] = None
    order: int = 0


class CheckCreate(CheckBase):
    category_id: int


class CheckUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[Severity] = None
    how_to_validate: Optional[str] = None
    expected_evidence: Optional[str] = None
    recommendations: Optional[str] = None
    mapping_owasp_asvs: Optional[str] = None
    mapping_owasp_top10: Optional[str] = None
    mapping_cwe: Optional[str] = None
    has_automated_test: Optional[bool] = None
    test_type: Optional[str] = None
    test_config: Optional[dict] = None
    is_active: Optional[bool] = None
    order: Optional[int] = None


class CheckResponse(CheckBase):
    id: int
    category_id: int
    is_active: bool
    
    class Config:
        from_attributes = True


class CheckWithCategory(CheckResponse):
    category_name: Optional[str] = None
    category_code: Optional[str] = None


# ============== CHECK RESULT SCHEMAS ==============

class CheckResultBase(BaseModel):
    status: CheckStatus = CheckStatus.NOT_STARTED
    notes: Optional[str] = None
    evidence: Optional[str] = None


class CheckResultCreate(CheckResultBase):
    application_id: int
    check_id: int


class CheckResultUpdate(BaseModel):
    status: Optional[CheckStatus] = None
    notes: Optional[str] = None
    evidence: Optional[str] = None
    comment: Optional[str] = None  # For history


class CheckResultResponse(CheckResultBase):
    id: int
    application_id: int
    check_id: int
    responsible_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class CheckResultWithDetails(CheckResultResponse):
    check: Optional[CheckWithCategory] = None
    attachments: List[Any] = []
    last_test_result: Optional[Any] = None


# ============== ATTACHMENT SCHEMAS ==============

class AttachmentResponse(BaseModel):
    id: int
    filename: str
    original_filename: str
    file_size: Optional[int] = None
    mime_type: Optional[str] = None
    uploaded_at: datetime
    
    class Config:
        from_attributes = True


# ============== HISTORY SCHEMAS ==============

class CheckHistoryResponse(BaseModel):
    id: int
    old_status: Optional[CheckStatus] = None
    new_status: CheckStatus
    comment: Optional[str] = None
    changes: Optional[dict] = None
    created_at: datetime
    user_id: int
    username: Optional[str] = None
    
    class Config:
        from_attributes = True


# ============== TEST EXECUTION SCHEMAS ==============

class TestExecutionRequest(BaseModel):
    application_id: int
    check_id: int
    target_url: Optional[str] = None
    custom_config: Optional[dict] = None


class TestExecutionResponse(BaseModel):
    id: int
    application_id: int
    check_id: int
    result: TestResult
    output: Optional[str] = None
    details: Optional[dict] = None
    duration_ms: Optional[int] = None
    executed_at: datetime
    executed_by_id: Optional[int] = None
    
    class Config:
        from_attributes = True


# ============== ACTION PLAN SCHEMAS ==============

class ActionPlanBase(BaseModel):
    task: str
    priority: Severity = Severity.MEDIUM
    status: str = "pending"
    due_date: Optional[datetime] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class ActionPlanCreate(ActionPlanBase):
    application_id: int
    check_id: Optional[int] = None


class ActionPlanUpdate(BaseModel):
    task: Optional[str] = None
    priority: Optional[Severity] = None
    status: Optional[str] = None
    due_date: Optional[datetime] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None


class ActionPlanResponse(ActionPlanBase):
    id: int
    application_id: int
    check_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ============== REPORT SCHEMAS ==============

class ReportSummary(BaseModel):
    application: ApplicationResponse
    stats: ApplicationStats
    by_severity: dict
    by_category: dict
    failed_checks: List[CheckResultWithDetails]
    action_plans: List[ActionPlanResponse]
    generated_at: datetime


# ============== DASHBOARD SCHEMAS ==============

class DashboardStats(BaseModel):
    total_applications: int
    total_checks: int
    overall_compliance: float
    critical_findings: int
    high_findings: int
    recent_tests: List[TestExecutionResponse]
    applications_summary: List[dict]
