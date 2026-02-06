"""
Security Checklist Application - Database Models
"""
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean, 
    ForeignKey, Enum as SQLEnum, Float, JSON
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime
import enum

Base = declarative_base()


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    AUDITOR = "auditor"
    DEV = "dev"


class CheckStatus(str, enum.Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    APPROVED = "approved"
    FAILED = "failed"
    NOT_APPLICABLE = "na"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(str, enum.Enum):
    DEV = "dev"
    HML = "hml"
    PROD = "prod"


class TestResult(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    ERROR = "error"
    NOT_RUN = "not_run"


# ============== USER MANAGEMENT ==============

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(SQLEnum(UserRole), default=UserRole.DEV, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    check_results = relationship("CheckResult", back_populates="responsible_user")
    check_history = relationship("CheckHistory", back_populates="user")
    test_executions = relationship("TestExecution", back_populates="executed_by_user")


# ============== APPLICATION MANAGEMENT ==============

class Application(Base):
    __tablename__ = "applications"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    environment = Column(SQLEnum(Environment), default=Environment.DEV)
    base_url = Column(String(500), nullable=True)
    tags = Column(String(500), nullable=True)  # Comma-separated tags
    responsible = Column(String(100), nullable=True)
    
    # Scope
    scope_urls = Column(Text, nullable=True)  # JSON array of URLs
    scope_endpoints = Column(Text, nullable=True)  # JSON array of endpoints
    scope_credentials_hint = Column(String(500), nullable=True)  # Just a hint, never actual credentials
    scope_notes = Column(Text, nullable=True)
    
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    check_results = relationship("CheckResult", back_populates="application", cascade="all, delete-orphan")
    test_executions = relationship("TestExecution", back_populates="application", cascade="all, delete-orphan")
    action_plans = relationship("ActionPlan", back_populates="application", cascade="all, delete-orphan")


# ============== SECURITY CHECKS ==============

class Category(Base):
    __tablename__ = "categories"
    
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(10), unique=True, nullable=False)  # e.g., "EI", "AC", etc.
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    order = Column(Integer, default=0)
    icon = Column(String(50), nullable=True)  # CSS icon class
    
    # Relationships
    checks = relationship("Check", back_populates="category", cascade="all, delete-orphan")


class Check(Base):
    __tablename__ = "checks"
    
    id = Column(Integer, primary_key=True, index=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    code = Column(String(20), unique=True, nullable=False)  # e.g., "EI-001"
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), default=Severity.MEDIUM)
    
    # Validation guidance
    how_to_validate = Column(Text, nullable=True)  # Step-by-step instructions
    expected_evidence = Column(Text, nullable=True)
    recommendations = Column(Text, nullable=True)  # If check fails
    
    # Mappings (optional)
    mapping_owasp_asvs = Column(String(100), nullable=True)
    mapping_owasp_top10 = Column(String(100), nullable=True)
    mapping_cwe = Column(String(100), nullable=True)
    
    # Automation
    has_automated_test = Column(Boolean, default=False)
    test_type = Column(String(50), nullable=True)  # e.g., "header_check", "http_test", etc.
    test_config = Column(JSON, nullable=True)  # JSON config for automated tests
    
    is_active = Column(Boolean, default=True)
    order = Column(Integer, default=0)
    
    # Relationships
    category = relationship("Category", back_populates="checks")
    results = relationship("CheckResult", back_populates="check")


class CheckResult(Base):
    __tablename__ = "check_results"
    
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("checks.id"), nullable=False)
    
    status = Column(SQLEnum(CheckStatus), default=CheckStatus.NOT_STARTED)
    notes = Column(Text, nullable=True)  # Markdown supported
    evidence = Column(Text, nullable=True)  # Markdown evidence text
    responsible_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    application = relationship("Application", back_populates="check_results")
    check = relationship("Check", back_populates="results")
    responsible_user = relationship("User", back_populates="check_results")
    attachments = relationship("CheckAttachment", back_populates="check_result", cascade="all, delete-orphan")
    history = relationship("CheckHistory", back_populates="check_result", cascade="all, delete-orphan")


class CheckAttachment(Base):
    __tablename__ = "check_attachments"
    
    id = Column(Integer, primary_key=True, index=True)
    check_result_id = Column(Integer, ForeignKey("check_results.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    filepath = Column(String(500), nullable=False)
    file_size = Column(Integer, nullable=True)
    mime_type = Column(String(100), nullable=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    check_result = relationship("CheckResult", back_populates="attachments")


class CheckHistory(Base):
    __tablename__ = "check_history"
    
    id = Column(Integer, primary_key=True, index=True)
    check_result_id = Column(Integer, ForeignKey("check_results.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    old_status = Column(SQLEnum(CheckStatus), nullable=True)
    new_status = Column(SQLEnum(CheckStatus), nullable=False)
    comment = Column(Text, nullable=True)
    changes = Column(JSON, nullable=True)  # JSON of what changed
    
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    check_result = relationship("CheckResult", back_populates="history")
    user = relationship("User", back_populates="check_history")


# ============== TEST EXECUTION ==============

class TestExecution(Base):
    __tablename__ = "test_executions"
    
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("checks.id"), nullable=False)
    
    result = Column(SQLEnum(TestResult), default=TestResult.NOT_RUN)
    output = Column(Text, nullable=True)  # Test output/logs
    details = Column(JSON, nullable=True)  # Detailed results in JSON
    duration_ms = Column(Integer, nullable=True)
    
    executed_at = Column(DateTime, default=datetime.utcnow)
    executed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    application = relationship("Application", back_populates="test_executions")
    executed_by_user = relationship("User", back_populates="test_executions")


# ============== ACTION PLANS ==============

class ActionPlan(Base):
    __tablename__ = "action_plans"
    
    id = Column(Integer, primary_key=True, index=True)
    application_id = Column(Integer, ForeignKey("applications.id"), nullable=False)
    check_id = Column(Integer, ForeignKey("checks.id"), nullable=True)
    
    task = Column(Text, nullable=False)
    priority = Column(SQLEnum(Severity), default=Severity.MEDIUM)
    status = Column(String(50), default="pending")  # pending, in_progress, completed
    due_date = Column(DateTime, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    application = relationship("Application", back_populates="action_plans")


# ============== AUDIT LOG ==============

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    entity_type = Column(String(50), nullable=True)
    entity_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
