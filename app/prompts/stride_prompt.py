"""
app/prompts/stride_prompt.py
Prompt engineering for STRIDE threat analysis.

Design principles:
  1. Expert persona system prompt
  2. Structured chain-of-thought instructions
  3. Few-shot examples for calibration
  4. Strict JSON output schema enforcement
  5. Context injection for grounded analysis
"""

SYSTEM_PROMPT = """You are a senior application security architect with 15+ years of experience
in threat modeling using the STRIDE methodology. You have conducted security reviews for
Fortune 500 companies and are an expert in cloud architectures, microservices, APIs, and
distributed systems security.

Your task is to analyze architecture diagrams and produce structured threat models.
You are meticulous, thorough, and always base your analysis on what is actually visible
in the diagram — never inventing components that are not shown.

You MUST return ONLY valid JSON matching the specified schema — no markdown, no prose,
no explanations outside the JSON structure.
"""


def build_user_prompt(context: str | None = None) -> str:
    """
    Build the user-turn prompt with optional application context injection.
    """
    context_block = ""
    if context:
        context_block = f"""
## Additional Context Provided by User

{context}

Use this context to make your analysis more specific and accurate.
"""

    return f"""Analyze the architecture diagram in the attached image and produce a comprehensive
STRIDE threat model.
{context_block}
## Analysis Steps (Chain-of-Thought)

1. **Architecture Understanding**
   - Identify all visible components (services, databases, queues, users, external systems)
   - Map the data flows between components
   - Note authentication/authorization boundaries
   - Identify trust zones and boundaries

2. **STRIDE Analysis — For each component and data flow, evaluate:**

   | Category | Letter | Ask yourself |
   |----------|--------|-------------|
   | Spoofing | S | Can an attacker impersonate a user, service, or system? |
   | Tampering | T | Can data be modified in transit or at rest? |
   | Repudiation | R | Can users deny performing actions? Are there audit logs? |
   | Information Disclosure | I | Can sensitive data be exposed unintentionally? |
   | Denial of Service | D | Can the system be made unavailable? |
   | Elevation of Privilege | E | Can a user gain more privileges than intended? |

3. **Risk Assessment** — For each threat:
   - Likelihood: HIGH / MEDIUM / LOW
   - Impact: CRITICAL / HIGH / MEDIUM / LOW
   - Overall Risk = max(Likelihood, Impact) with judgment

4. **Mitigations** — Provide 2-4 concrete, actionable mitigations per threat.

## Few-Shot Examples

### Example Threat — Spoofing
```json
{{
  "id": "T001",
  "category": "Spoofing",
  "stride_letter": "S",
  "title": "JWT token forgery at API Gateway",
  "description": "An attacker could forge or replay JWT tokens to impersonate legitimate users if the gateway does not validate token signatures properly.",
  "affected_components": ["API Gateway", "Auth Service"],
  "risk_level": "HIGH",
  "likelihood": "MEDIUM",
  "impact": "HIGH",
  "mitigations": [
    "Validate JWT signatures using asymmetric keys (RS256)",
    "Implement short token expiration (15 min) with refresh token rotation",
    "Add token revocation list (Redis-based blacklist)"
  ],
  "references": ["OWASP A07:2021", "CWE-287"]
}}
```

### Example Threat — Denial of Service
```json
{{
  "id": "T005",
  "category": "Denial of Service",
  "stride_letter": "D",
  "title": "Unprotected public API endpoint susceptible to DDoS",
  "description": "The public-facing API has no rate limiting, allowing an attacker to flood it with requests and degrade availability for legitimate users.",
  "affected_components": ["Load Balancer", "API Gateway"],
  "risk_level": "HIGH",
  "likelihood": "HIGH",
  "impact": "HIGH",
  "mitigations": [
    "Implement rate limiting (e.g., 100 req/min per IP)",
    "Add WAF (Web Application Firewall) rules",
    "Use Azure DDoS Protection Standard",
    "Implement exponential backoff on client retries"
  ],
  "references": ["OWASP A05:2021", "CWE-400"]
}}
```

## Required JSON Output Schema

Return ONLY this JSON structure — no markdown code blocks, no extra text:

{{
  "architecture_summary": "string — describe what you see in the diagram in 2-3 sentences",
  "threats": [
    {{
      "id": "T001",
      "category": "Spoofing | Tampering | Repudiation | Information Disclosure | Denial of Service | Elevation of Privilege",
      "stride_letter": "S | T | R | I | D | E",
      "title": "short threat title",
      "description": "detailed description of the threat",
      "affected_components": ["component1", "component2"],
      "risk_level": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
      "likelihood": "HIGH | MEDIUM | LOW",
      "impact": "CRITICAL | HIGH | MEDIUM | LOW",
      "mitigations": ["mitigation 1", "mitigation 2"],
      "references": ["OWASP ...", "CWE-..."]
    }}
  ],
  "recommendations": [
    "Top 3-5 priority actions across all findings"
  ]
}}

Be thorough — identify at least 6-10 threats covering all 6 STRIDE categories if the
architecture is complex enough. If the image is not an architecture diagram, return an
empty threats array and explain in architecture_summary.
"""
