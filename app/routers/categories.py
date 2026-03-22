"""
app/routers/categories.py
GET /api/v1/categories — STRIDE reference endpoint.
"""

from fastapi import APIRouter

router = APIRouter()

STRIDE_REFERENCE = [
    {
        "letter": "S",
        "category": "Spoofing",
        "violated_property": "Authenticity",
        "description": "Impersonating a user, process, or system to gain unauthorized access.",
        "examples": [
            "Stealing authentication tokens",
            "DNS spoofing to redirect traffic",
            "Forging certificates",
        ],
        "common_mitigations": [
            "Strong authentication (MFA, certificates)",
            "Mutual TLS (mTLS) between services",
            "Token validation and short expiration",
        ],
    },
    {
        "letter": "T",
        "category": "Tampering",
        "violated_property": "Integrity",
        "description": "Unauthorized modification of data in transit or at rest.",
        "examples": [
            "Man-in-the-middle attack on API calls",
            "SQL injection to modify database records",
            "Modifying configuration files",
        ],
        "common_mitigations": [
            "TLS/HTTPS for all communications",
            "Data signing (HMAC, digital signatures)",
            "Input validation and parameterized queries",
        ],
    },
    {
        "letter": "R",
        "category": "Repudiation",
        "violated_property": "Non-repudiation",
        "description": "Users denying they performed an action due to insufficient audit trails.",
        "examples": [
            "Deleting logs after a transaction",
            "Performing actions without traceable identity",
        ],
        "common_mitigations": [
            "Centralized, tamper-proof audit logging",
            "Digital signatures on critical transactions",
            "Time-stamping with trusted third party",
        ],
    },
    {
        "letter": "I",
        "category": "Information Disclosure",
        "violated_property": "Confidentiality",
        "description": "Exposing sensitive data to unauthorized parties.",
        "examples": [
            "Unencrypted PII in database",
            "Verbose error messages leaking stack traces",
            "Insecure direct object references",
        ],
        "common_mitigations": [
            "Encryption at rest and in transit",
            "Principle of least privilege",
            "Data masking and tokenization",
        ],
    },
    {
        "letter": "D",
        "category": "Denial of Service",
        "violated_property": "Availability",
        "description": "Making a system or service unavailable to legitimate users.",
        "examples": [
            "DDoS flooding a public endpoint",
            "Resource exhaustion through slow-loris attack",
            "Exploiting unbounded operations",
        ],
        "common_mitigations": [
            "Rate limiting and throttling",
            "WAF and DDoS protection",
            "Auto-scaling and circuit breakers",
        ],
    },
    {
        "letter": "E",
        "category": "Elevation of Privilege",
        "violated_property": "Authorization",
        "description": "Gaining higher access rights than intended.",
        "examples": [
            "Exploiting IDOR to access other users' data",
            "SQL injection granting admin access",
            "Container escape to host system",
        ],
        "common_mitigations": [
            "Role-Based Access Control (RBAC)",
            "Principle of least privilege",
            "Regular permission audits",
        ],
    },
]


@router.get(
    "/categories",
    summary="STRIDE categories reference",
    description="Returns the 6 STRIDE threat categories with descriptions, examples, and mitigations.",
)
async def get_stride_categories():
    return {"categories": STRIDE_REFERENCE}
