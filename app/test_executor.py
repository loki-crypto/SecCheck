"""
Security Checklist Application - Security Test Executor
Safe-by-design tests for defensive security verification
"""
import httpx
import asyncio
import re
import json
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class TestType(str, Enum):
    HEADER_CHECK = "header_check"
    HTTP_METHODS = "http_methods"
    COOKIE_CHECK = "cookie_check"
    TLS_CHECK = "tls_check"
    ENDPOINT_CHECK = "endpoint_check"
    AUTH_CHECK = "auth_check"
    INPUT_VALIDATION = "input_validation"
    ERROR_HANDLING = "error_handling"
    CORS_CHECK = "cors_check"
    RATE_LIMIT_CHECK = "rate_limit_check"


@dataclass
class TestResult:
    passed: bool
    result: str  # "pass", "fail", "warn", "error"
    message: str
    details: Dict[str, Any]
    duration_ms: int


class SecurityTestExecutor:
    """
    Executor for safe security tests.
    All tests are defensive and do not attempt exploitation.
    """
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.client = None
    
    async def __aenter__(self):
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=True
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
    
    async def execute_test(
        self, 
        test_type: str, 
        target_url: str, 
        config: Optional[Dict] = None
    ) -> TestResult:
        """Execute a security test based on type"""
        start_time = datetime.utcnow()
        
        try:
            config = config or {}
            
            if test_type == TestType.HEADER_CHECK:
                result = await self.check_security_headers(target_url, config)
            elif test_type == TestType.HTTP_METHODS:
                result = await self.check_http_methods(target_url, config)
            elif test_type == TestType.COOKIE_CHECK:
                result = await self.check_cookie_security(target_url, config)
            elif test_type == TestType.TLS_CHECK:
                result = await self.check_tls_config(target_url, config)
            elif test_type == TestType.ENDPOINT_CHECK:
                result = await self.check_exposed_endpoints(target_url, config)
            elif test_type == TestType.CORS_CHECK:
                result = await self.check_cors_config(target_url, config)
            elif test_type == TestType.ERROR_HANDLING:
                result = await self.check_error_handling(target_url, config)
            elif test_type == TestType.RATE_LIMIT_CHECK:
                result = await self.check_rate_limiting(target_url, config)
            else:
                result = TestResult(
                    passed=False,
                    result="error",
                    message=f"Unknown test type: {test_type}",
                    details={},
                    duration_ms=0
                )
            
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            result.duration_ms = int(duration)
            return result
            
        except httpx.ConnectError as e:
            return TestResult(
                passed=False,
                result="error",
                message=f"Connection failed: {str(e)}",
                details={"error_type": "connection_error"},
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
        except httpx.TimeoutException:
            return TestResult(
                passed=False,
                result="error",
                message="Request timed out",
                details={"error_type": "timeout"},
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
        except Exception as e:
            logger.error(f"Test execution error: {str(e)}")
            return TestResult(
                passed=False,
                result="error",
                message=f"Test error: {str(e)}",
                details={"error_type": "exception"},
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )
    
    async def check_security_headers(self, url: str, config: Dict) -> TestResult:
        """Check for presence and correct configuration of security headers"""
        
        required_headers = config.get("required_headers", {
            "Strict-Transport-Security": {
                "required": True,
                "pattern": r"max-age=\d+",
                "recommendation": "Add HSTS header with max-age >= 31536000"
            },
            "X-Content-Type-Options": {
                "required": True,
                "expected": "nosniff",
                "recommendation": "Set X-Content-Type-Options: nosniff"
            },
            "X-Frame-Options": {
                "required": True,
                "pattern": r"^(DENY|SAMEORIGIN)$",
                "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN"
            },
            "Content-Security-Policy": {
                "required": True,
                "pattern": r".+",
                "recommendation": "Implement a Content Security Policy"
            },
            "X-XSS-Protection": {
                "required": False,
                "expected": "0",
                "recommendation": "Modern browsers deprecated this; consider CSP instead"
            },
            "Referrer-Policy": {
                "required": True,
                "pattern": r"^(no-referrer|strict-origin|strict-origin-when-cross-origin)$",
                "recommendation": "Set appropriate Referrer-Policy"
            },
            "Permissions-Policy": {
                "required": False,
                "pattern": r".+",
                "recommendation": "Consider implementing Permissions-Policy"
            }
        })
        
        response = await self.client.get(url)
        headers = dict(response.headers)
        
        findings = []
        passed_checks = []
        failed_checks = []
        warnings = []
        
        for header_name, rules in required_headers.items():
            header_value = headers.get(header_name.lower()) or headers.get(header_name)
            
            if header_value:
                # Check expected value
                if "expected" in rules:
                    if header_value.lower() == rules["expected"].lower():
                        passed_checks.append(f"✓ {header_name}: {header_value}")
                    else:
                        failed_checks.append(f"✗ {header_name}: Expected '{rules['expected']}', got '{header_value}'")
                # Check pattern
                elif "pattern" in rules:
                    if re.match(rules["pattern"], header_value, re.IGNORECASE):
                        passed_checks.append(f"✓ {header_name}: {header_value}")
                    else:
                        failed_checks.append(f"✗ {header_name}: Value '{header_value}' doesn't match expected pattern")
                else:
                    passed_checks.append(f"✓ {header_name}: Present")
            else:
                if rules.get("required", False):
                    failed_checks.append(f"✗ {header_name}: Missing - {rules.get('recommendation', '')}")
                else:
                    warnings.append(f"⚠ {header_name}: Not present (optional)")
        
        # Check for information disclosure headers
        info_disclosure_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]
        for header in info_disclosure_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                warnings.append(f"⚠ {header} header exposes server information")
        
        all_passed = len(failed_checks) == 0
        
        return TestResult(
            passed=all_passed,
            result="pass" if all_passed else ("warn" if len(failed_checks) < 3 else "fail"),
            message=f"Checked {len(required_headers)} security headers. {len(passed_checks)} passed, {len(failed_checks)} failed, {len(warnings)} warnings.",
            details={
                "url": url,
                "status_code": response.status_code,
                "passed_checks": passed_checks,
                "failed_checks": failed_checks,
                "warnings": warnings,
                "all_headers": {k: v for k, v in headers.items() if not k.startswith(":")},
                "recommendations": [rules.get("recommendation") for header_name, rules in required_headers.items() 
                                   if not (headers.get(header_name.lower()) or headers.get(header_name)) and rules.get("required")]
            },
            duration_ms=0
        )
    
    async def check_http_methods(self, url: str, config: Dict) -> TestResult:
        """Check which HTTP methods are allowed"""
        
        methods_to_test = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
        dangerous_methods = ["TRACE", "TRACK", "DEBUG"]
        
        results = {}
        issues = []
        
        for method in methods_to_test:
            try:
                response = await self.client.request(method, url)
                results[method] = {
                    "status_code": response.status_code,
                    "allowed": response.status_code not in [405, 501]
                }
                
                if method in dangerous_methods and response.status_code not in [405, 501]:
                    issues.append(f"⚠ Dangerous method {method} appears to be allowed (status: {response.status_code})")
                    
            except Exception as e:
                results[method] = {"status_code": None, "allowed": False, "error": str(e)}
        
        # Check OPTIONS for CORS preflight
        if results.get("OPTIONS", {}).get("allowed"):
            try:
                response = await self.client.options(url)
                allow_header = response.headers.get("Allow", "")
                if allow_header:
                    results["allowed_methods_header"] = allow_header
            except:
                pass
        
        passed = len(issues) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else "warn",
            message=f"Tested {len(methods_to_test)} HTTP methods. {len(issues)} potential issues found.",
            details={
                "url": url,
                "methods": results,
                "issues": issues,
                "recommendations": [
                    "Disable TRACE and TRACK methods",
                    "Only allow necessary HTTP methods for each endpoint",
                    "Implement proper method validation"
                ] if issues else []
            },
            duration_ms=0
        )
    
    async def check_cookie_security(self, url: str, config: Dict) -> TestResult:
        """Check cookie security attributes"""
        
        response = await self.client.get(url)
        cookies = response.cookies
        set_cookie_headers = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else []
        
        # Parse Set-Cookie headers manually if needed
        if not set_cookie_headers:
            set_cookie_headers = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
        
        findings = []
        issues = []
        
        for cookie_header in set_cookie_headers:
            cookie_lower = cookie_header.lower()
            cookie_name = cookie_header.split("=")[0] if "=" in cookie_header else "unknown"
            
            cookie_info = {
                "name": cookie_name,
                "secure": "secure" in cookie_lower,
                "httponly": "httponly" in cookie_lower,
                "samesite": None
            }
            
            # Check SameSite
            if "samesite=strict" in cookie_lower:
                cookie_info["samesite"] = "Strict"
            elif "samesite=lax" in cookie_lower:
                cookie_info["samesite"] = "Lax"
            elif "samesite=none" in cookie_lower:
                cookie_info["samesite"] = "None"
            
            findings.append(cookie_info)
            
            # Check for issues
            if not cookie_info["secure"] and url.startswith("https"):
                issues.append(f"Cookie '{cookie_name}' missing Secure flag")
            if not cookie_info["httponly"]:
                issues.append(f"Cookie '{cookie_name}' missing HttpOnly flag")
            if not cookie_info["samesite"]:
                issues.append(f"Cookie '{cookie_name}' missing SameSite attribute")
            elif cookie_info["samesite"] == "None" and not cookie_info["secure"]:
                issues.append(f"Cookie '{cookie_name}' has SameSite=None but no Secure flag")
        
        if not set_cookie_headers:
            return TestResult(
                passed=True,
                result="pass",
                message="No cookies set by the response",
                details={"url": url, "cookies_found": 0},
                duration_ms=0
            )
        
        passed = len(issues) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else "fail",
            message=f"Analyzed {len(findings)} cookies. {len(issues)} security issues found.",
            details={
                "url": url,
                "cookies": findings,
                "issues": issues,
                "recommendations": [
                    "Set Secure flag on all cookies for HTTPS sites",
                    "Set HttpOnly flag on session cookies",
                    "Use SameSite=Strict or SameSite=Lax",
                    "Consider cookie prefixes (__Host- or __Secure-)"
                ] if issues else []
            },
            duration_ms=0
        )
    
    async def check_tls_config(self, url: str, config: Dict) -> TestResult:
        """Basic TLS configuration check"""
        
        if not url.startswith("https://"):
            return TestResult(
                passed=False,
                result="fail",
                message="URL does not use HTTPS",
                details={
                    "url": url,
                    "issue": "Application not using HTTPS",
                    "recommendations": ["Enable HTTPS/TLS for all traffic"]
                },
                duration_ms=0
            )
        
        issues = []
        info = {}
        
        try:
            # Make request to check TLS works
            response = await self.client.get(url)
            info["status_code"] = response.status_code
            info["https_working"] = True
            
            # Check HSTS
            hsts = response.headers.get("strict-transport-security")
            if hsts:
                info["hsts"] = hsts
                if "max-age" in hsts:
                    max_age = int(re.search(r"max-age=(\d+)", hsts).group(1))
                    if max_age < 31536000:
                        issues.append(f"HSTS max-age ({max_age}) is less than recommended (31536000)")
                    else:
                        info["hsts_adequate"] = True
            else:
                issues.append("HSTS header not present")
            
            # Check for HTTP to HTTPS redirect
            http_url = url.replace("https://", "http://")
            try:
                http_client = httpx.AsyncClient(timeout=5, follow_redirects=False)
                http_response = await http_client.get(http_url)
                await http_client.aclose()
                
                if http_response.status_code in [301, 302, 307, 308]:
                    location = http_response.headers.get("location", "")
                    if location.startswith("https://"):
                        info["http_redirects_to_https"] = True
                    else:
                        issues.append("HTTP does not redirect to HTTPS")
                else:
                    issues.append("HTTP endpoint accessible without redirect to HTTPS")
            except:
                info["http_check"] = "Could not check HTTP endpoint"
            
        except httpx.ConnectError as e:
            if "SSL" in str(e) or "certificate" in str(e).lower():
                issues.append(f"TLS/SSL error: {str(e)}")
            else:
                raise
        
        passed = len(issues) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else "warn",
            message=f"TLS configuration check completed. {len(issues)} issues found.",
            details={
                "url": url,
                "info": info,
                "issues": issues,
                "recommendations": [
                    "Enable HSTS with max-age >= 31536000",
                    "Include 'includeSubDomains' in HSTS",
                    "Consider HSTS preload",
                    "Ensure HTTP redirects to HTTPS"
                ] if issues else []
            },
            duration_ms=0
        )
    
    async def check_exposed_endpoints(self, url: str, config: Dict) -> TestResult:
        """Check for commonly exposed sensitive endpoints"""
        
        # Safe endpoints to check - these are defensive checks
        common_paths = config.get("paths", [
            # Admin/management
            "/admin", "/administrator", "/admin.php", "/wp-admin",
            "/manager", "/management", "/console",
            
            # Debug/development
            "/debug", "/phpinfo.php", "/info.php",
            "/server-status", "/server-info",
            "/.env", "/config.php", "/configuration.php",
            
            # API documentation
            "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
            "/graphql", "/graphiql",
            
            # Version control
            "/.git/config", "/.svn/entries",
            
            # Backup files
            "/backup", "/backup.sql", "/database.sql",
            
            # Common configs
            "/web.config", "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/robots.txt", "/sitemap.xml",
            
            # Error pages
            "/error", "/errors", "/404", "/500"
        ])
        
        findings = []
        exposed = []
        protected = []
        
        base_url = url.rstrip("/")
        
        for path in common_paths:
            try:
                test_url = f"{base_url}{path}"
                response = await self.client.get(test_url)
                
                finding = {
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": len(response.content)
                }
                
                # Consider exposed if returns 200 or has significant content
                if response.status_code == 200:
                    # Check if it's a real page vs generic response
                    if len(response.content) > 500:
                        finding["exposed"] = True
                        exposed.append(finding)
                    else:
                        finding["exposed"] = False
                        protected.append(finding)
                elif response.status_code in [401, 403]:
                    finding["protected"] = True
                    finding["exposed"] = False
                    protected.append(finding)
                else:
                    finding["exposed"] = False
                    protected.append(finding)
                    
            except Exception as e:
                findings.append({"path": path, "error": str(e)})
        
        # Categorize exposed endpoints
        sensitive_exposed = [e for e in exposed if any(
            pattern in e["path"].lower() 
            for pattern in ["admin", "config", ".env", ".git", "debug", "backup", "sql"]
        )]
        
        passed = len(sensitive_exposed) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else "fail",
            message=f"Checked {len(common_paths)} common paths. {len(exposed)} accessible, {len(sensitive_exposed)} potentially sensitive.",
            details={
                "base_url": base_url,
                "total_checked": len(common_paths),
                "exposed_endpoints": exposed,
                "sensitive_exposed": sensitive_exposed,
                "protected_endpoints": protected[:10],  # Limit output
                "recommendations": [
                    "Restrict access to admin endpoints",
                    "Remove or protect debug endpoints",
                    "Block access to configuration files",
                    "Remove version control directories from production"
                ] if sensitive_exposed else []
            },
            duration_ms=0
        )
    
    async def check_cors_config(self, url: str, config: Dict) -> TestResult:
        """Check CORS configuration"""
        
        test_origins = config.get("test_origins", [
            "https://evil.com",
            "https://attacker.example.com",
            "null"
        ])
        
        issues = []
        findings = []
        
        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = await self.client.options(url, headers=headers)
                
                acao = response.headers.get("access-control-allow-origin")
                acac = response.headers.get("access-control-allow-credentials")
                
                finding = {
                    "test_origin": origin,
                    "acao": acao,
                    "acac": acac,
                    "status_code": response.status_code
                }
                findings.append(finding)
                
                # Check for dangerous configurations
                if acao == "*":
                    if acac and acac.lower() == "true":
                        issues.append(f"Dangerous: ACAO=* with credentials allowed")
                    else:
                        issues.append(f"⚠ CORS allows all origins (ACAO=*)")
                
                if acao == origin and origin in ["https://evil.com", "https://attacker.example.com"]:
                    issues.append(f"CORS reflects arbitrary origin: {origin}")
                    if acac and acac.lower() == "true":
                        issues.append(f"Critical: Arbitrary origin with credentials for {origin}")
                
                if acao == "null":
                    issues.append("CORS allows null origin")
                    
            except Exception as e:
                findings.append({"test_origin": origin, "error": str(e)})
        
        passed = len(issues) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else ("fail" if "Critical" in str(issues) else "warn"),
            message=f"CORS configuration check completed. {len(issues)} issues found.",
            details={
                "url": url,
                "findings": findings,
                "issues": issues,
                "recommendations": [
                    "Avoid ACAO=* in production",
                    "Use specific allowed origins",
                    "Don't allow credentials with wildcard origin",
                    "Validate Origin header server-side"
                ] if issues else []
            },
            duration_ms=0
        )
    
    async def check_error_handling(self, url: str, config: Dict) -> TestResult:
        """Check error handling for information disclosure"""
        
        test_cases = [
            {"path": "/nonexistent-page-12345", "expected": 404},
            {"path": "/' OR '1'='1", "type": "path_injection"},
            {"path": "/../../../etc/passwd", "type": "path_traversal"},
            {"path": "/?id=999999999", "type": "invalid_param"},
        ]
        
        issues = []
        findings = []
        
        base_url = url.rstrip("/")
        
        for test in test_cases:
            try:
                test_url = f"{base_url}{test['path']}"
                response = await self.client.get(test_url)
                
                content = response.text.lower()
                headers = dict(response.headers)
                
                finding = {
                    "test": test.get("type", "standard"),
                    "path": test["path"],
                    "status_code": response.status_code
                }
                
                # Check for information disclosure in error pages
                disclosure_patterns = [
                    ("stack trace", "Stack trace exposed"),
                    ("exception", "Exception details exposed"),
                    ("traceback", "Python traceback exposed"),
                    ("at line", "Line number exposed"),
                    ("sql syntax", "SQL error exposed"),
                    ("mysql", "Database type exposed"),
                    ("postgresql", "Database type exposed"),
                    ("ora-", "Oracle error exposed"),
                    ("microsoft ole db", "Database error exposed"),
                    ("php warning", "PHP warning exposed"),
                    ("php error", "PHP error exposed"),
                    ("asp.net", "Framework exposed"),
                    ("django", "Framework exposed"),
                    ("laravel", "Framework exposed"),
                    ("/var/www", "Server path exposed"),
                    ("c:\\", "Server path exposed"),
                ]
                
                for pattern, message in disclosure_patterns:
                    if pattern in content:
                        finding["disclosure"] = message
                        issues.append(f"Information disclosure: {message} on {test['path']}")
                        break
                
                # Check for verbose error headers
                verbose_headers = ["X-Powered-By", "Server", "X-AspNet-Version"]
                for h in verbose_headers:
                    if h.lower() in [k.lower() for k in headers.keys()]:
                        if h not in str(findings):  # Avoid duplicates
                            issues.append(f"Verbose header present: {h}")
                
                findings.append(finding)
                
            except Exception as e:
                findings.append({"test": test.get("type", "standard"), "error": str(e)})
        
        passed = len(issues) == 0
        
        return TestResult(
            passed=passed,
            result="pass" if passed else "warn",
            message=f"Error handling check completed. {len(issues)} potential information disclosures found.",
            details={
                "url": url,
                "findings": findings,
                "issues": list(set(issues)),  # Remove duplicates
                "recommendations": [
                    "Use custom error pages",
                    "Disable detailed error messages in production",
                    "Remove verbose headers",
                    "Log errors server-side instead of displaying"
                ] if issues else []
            },
            duration_ms=0
        )
    
    async def check_rate_limiting(self, url: str, config: Dict) -> TestResult:
        """Check if rate limiting is implemented"""
        
        num_requests = config.get("num_requests", 20)
        
        responses = []
        rate_limited = False
        
        for i in range(num_requests):
            try:
                response = await self.client.get(url)
                responses.append({
                    "request_num": i + 1,
                    "status_code": response.status_code,
                    "rate_limit_headers": {
                        k: v for k, v in response.headers.items() 
                        if "rate" in k.lower() or "limit" in k.lower() or "retry" in k.lower()
                    }
                })
                
                if response.status_code == 429:
                    rate_limited = True
                    break
                    
            except Exception as e:
                responses.append({"request_num": i + 1, "error": str(e)})
            
            await asyncio.sleep(0.1)  # Small delay between requests
        
        # Check for rate limit headers
        has_rate_headers = any(r.get("rate_limit_headers") for r in responses)
        
        if rate_limited:
            result = "pass"
            message = f"Rate limiting detected after {len(responses)} requests"
            passed = True
        elif has_rate_headers:
            result = "pass"
            message = "Rate limit headers present but not triggered"
            passed = True
        else:
            result = "warn"
            message = f"No rate limiting detected after {num_requests} requests"
            passed = False
        
        return TestResult(
            passed=passed,
            result=result,
            message=message,
            details={
                "url": url,
                "requests_made": len(responses),
                "rate_limited": rate_limited,
                "has_rate_headers": has_rate_headers,
                "sample_responses": responses[:5],  # First 5
                "recommendations": [
                    "Implement rate limiting on all endpoints",
                    "Use rate limit headers (X-RateLimit-*)",
                    "Consider using a WAF for DDoS protection"
                ] if not passed else []
            },
            duration_ms=0
        )


# Helper function for running tests
async def run_security_test(
    test_type: str,
    target_url: str,
    config: Optional[Dict] = None
) -> TestResult:
    """Convenience function to run a single security test"""
    async with SecurityTestExecutor() as executor:
        return await executor.execute_test(test_type, target_url, config)


# Batch test runner
async def run_all_tests(target_url: str, tests: List[str] = None) -> Dict[str, TestResult]:
    """Run multiple security tests"""
    if tests is None:
        tests = [t.value for t in TestType]
    
    results = {}
    async with SecurityTestExecutor() as executor:
        for test_type in tests:
            results[test_type] = await executor.execute_test(test_type, target_url, {})
    
    return results
