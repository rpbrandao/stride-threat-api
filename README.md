# 🛡️ STRIDE Threat Analysis API

> **API inteligente** que recebe imagens de arquitetura de software e gera automaticamente análises de ameaças usando a metodologia **STRIDE**, powered by **FastAPI + Azure OpenAI GPT-4 Vision**.

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111+-009688?style=flat&logo=fastapi&logoColor=white)
![Azure OpenAI](https://img.shields.io/badge/Azure_OpenAI-GPT--4_Vision-0078D4?style=flat&logo=microsoft-azure&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)

</div>

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Metodologia STRIDE](#-metodologia-stride)
- [Arquitetura da Solução](#️-arquitetura-da-solução)
- [Tecnologias](#-tecnologias)
- [Pré-requisitos](#-pré-requisitos)
- [Instalação](#-instalação)
- [Configuração Azure OpenAI](#-configuração-azure-openai)
- [Como Usar](#-como-usar)
- [Endpoints da API](#-endpoints-da-api)
- [Prompt Engineering](#-prompt-engineering)
- [Exemplo de Resposta](#-exemplo-de-resposta)
- [Testes](#-testes)
- [Deploy com Docker](#-deploy-com-docker)
- [O que Aprendi](#-o-que-aprendi)

---

## 🎯 Sobre o Projeto

Este projeto implementa uma **API REST** capaz de:

1. **Receber** uma imagem de diagrama de arquitetura (PNG, JPG, PDF)
2. **Processar** a imagem com GPT-4 Vision via Azure OpenAI
3. **Analisar** ameaças usando a metodologia STRIDE
4. **Retornar** um relatório estruturado em JSON com todas as ameaças identificadas, nível de risco e recomendações de mitigação

### Exemplo de Uso

```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -H "Content-Type: multipart/form-data" \
  -F "image=@architecture.png" \
  -F "context=E-commerce application with microservices"
```

---

## 🎯 Metodologia STRIDE

A metodologia **STRIDE** foi criada pela Microsoft e é amplamente utilizada para modelagem de ameaças em sistemas de software.

| Letra | Categoria | Descrição | Viola |
|-------|-----------|-----------|-------|
| **S** | Spoofing | Falsificação de identidade | Autenticidade |
| **T** | Tampering | Adulteração de dados | Integridade |
| **R** | Repudiation | Negação de ações realizadas | Não-repúdio |
| **I** | Information Disclosure | Exposição indevida de dados | Confidencialidade |
| **D** | Denial of Service | Interrupção de serviços | Disponibilidade |
| **E** | Elevation of Privilege | Escalada de privilégios | Autorização |

### Por que STRIDE?

- ✅ Framework estruturado e reconhecido pela indústria
- ✅ Cobre as principais categorias de ameaças em sistemas distribuídos
- ✅ Facilmente mapeável para controles de segurança (ex: MITRE ATT&CK)
- ✅ Integrável com ciclos de desenvolvimento ágil (DevSecOps)

---

## 🏗️ Arquitetura da Solução

```
┌─────────────────────────────────────────────────────────────┐
│                        Cliente                               │
│              (curl / Swagger UI / Postman)                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTP POST /api/v1/analyze
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                     FastAPI Application                      │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │   Router    │→ │  Validation  │→ │  Image Service    │  │
│  │  /analyze   │  │  (Pydantic)  │  │  (base64 encode)  │  │
│  └─────────────┘  └──────────────┘  └────────┬──────────┘  │
│                                               │              │
│  ┌────────────────────────────────────────────▼──────────┐  │
│  │              STRIDE Analysis Service                   │  │
│  │   ┌──────────────┐    ┌─────────────────────────┐    │  │
│  │   │   Prompt     │    │   Azure OpenAI Client   │    │  │
│  │   │  Engineering │───▶│   GPT-4 Vision API      │    │  │
│  │   └──────────────┘    └─────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────┘  │
│                                               │              │
│  ┌────────────────────────────────────────────▼──────────┐  │
│  │              Response Builder                          │  │
│  │    StrideReport → JSON → HTTP 200                     │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tecnologias

| Tecnologia | Versão | Uso |
|------------|--------|-----|
| **Python** | 3.11+ | Linguagem principal |
| **FastAPI** | 0.111+ | Framework web assíncrono |
| **Azure OpenAI** | SDK v1.x | GPT-4 Vision para análise |
| **Pydantic v2** | 2.x | Validação e serialização |
| **Uvicorn** | 0.29+ | Servidor ASGI |
| **Python-dotenv** | 1.0+ | Gerenciamento de variáveis |
| **Pillow** | 10.x | Pré-processamento de imagens |
| **pytest** | 8.x | Testes unitários e integração |
| **Docker** | — | Containerização |

---

## 📦 Pré-requisitos

- Python 3.11+
- Conta Azure com recurso **Azure OpenAI** ativado
- Deployment do modelo **GPT-4 Vision** (gpt-4o ou gpt-4-vision-preview)
- Docker (opcional)

---

## 🚀 Instalação

### 1. Clone o repositório

```bash
git clone https://github.com/SEU_USUARIO/stride-threat-api.git
cd stride-threat-api
```

### 2. Crie e ative o ambiente virtual

```bash
python -m venv venv

# Linux/macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### 3. Instale as dependências

```bash
pip install -r requirements.txt
```

### 4. Configure as variáveis de ambiente

```bash
cp .env.example .env
# Edite o arquivo .env com suas credenciais Azure
```

### 5. Execute a aplicação

```bash
uvicorn app.main:app --reload --port 8000
```

Acesse a documentação interativa: **http://localhost:8000/docs**

---

## ☁️ Configuração Azure OpenAI

### Passo 1 — Criar recurso no Azure Portal

1. Acesse [portal.azure.com](https://portal.azure.com)
2. Crie um recurso **Azure OpenAI**
3. Anote o **Endpoint** e a **API Key**

### Passo 2 — Deploy do modelo

No **Azure AI Studio** (`oai.azure.com`):
1. Vá em **Deployments → Deploy model**
2. Escolha `gpt-4o` ou `gpt-4-turbo` (com suporte a visão)
3. Anote o **Deployment Name**

### Passo 3 — Variáveis de ambiente

```env
# .env
AZURE_OPENAI_ENDPOINT=https://SEU-RECURSO.openai.azure.com/
AZURE_OPENAI_API_KEY=sua_chave_aqui
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_API_VERSION=2024-02-15-preview
MAX_IMAGE_SIZE_MB=10
APP_ENV=development
```

---

## 📖 Como Usar

### Via Swagger UI

Acesse `http://localhost:8000/docs` e use o endpoint `/api/v1/analyze`.

### Via cURL

```bash
# Análise básica
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -F "image=@minha_arquitetura.png"

# Com contexto adicional
curl -X POST "http://localhost:8000/api/v1/analyze" \
  -F "image=@minha_arquitetura.png" \
  -F "context=Sistema bancário com autenticação OAuth2 e microserviços"

# Health check
curl http://localhost:8000/health
```

### Via Python

```python
import httpx

with open("architecture.png", "rb") as f:
    response = httpx.post(
        "http://localhost:8000/api/v1/analyze",
        files={"image": ("architecture.png", f, "image/png")},
        data={"context": "E-commerce com pagamentos integrados"},
    )

report = response.json()
for threat in report["threats"]:
    print(f"[{threat['category']}] {threat['title']} — Risco: {threat['risk_level']}")
```

---

## 🔌 Endpoints da API

### `POST /api/v1/analyze`

Analisa uma imagem de arquitetura e retorna o relatório STRIDE.

**Request (multipart/form-data):**

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `image` | file | ✅ | PNG, JPG ou PDF |
| `context` | string | ❌ | Contexto adicional da aplicação |

**Response (200 OK):**

```json
{
  "analysis_id": "uuid-...",
  "timestamp": "2025-03-21T10:00:00Z",
  "architecture_summary": "Sistema de e-commerce com API Gateway...",
  "threats": [
    {
      "id": "T001",
      "category": "Spoofing",
      "stride_letter": "S",
      "title": "Falsificação de identidade no API Gateway",
      "description": "Um atacante pode interceptar tokens JWT...",
      "affected_components": ["API Gateway", "Auth Service"],
      "risk_level": "HIGH",
      "likelihood": "MEDIUM",
      "impact": "HIGH",
      "mitigations": [
        "Implementar validação de assinatura JWT",
        "Usar mTLS entre serviços internos",
        "Adicionar rate limiting por IP"
      ],
      "references": ["OWASP A07:2021", "CWE-287"]
    }
  ],
  "summary": {
    "total_threats": 8,
    "by_category": {"S": 1, "T": 2, "R": 1, "I": 2, "D": 1, "E": 1},
    "by_risk_level": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 3, "LOW": 1}
  },
  "recommendations": [
    "Prioridade crítica: implementar autenticação mTLS...",
    "Revisar políticas de acesso ao banco de dados..."
  ]
}
```

### `GET /health`

```json
{"status": "healthy", "version": "1.0.0"}
```

### `GET /api/v1/categories`

Retorna descrição das 6 categorias STRIDE.

---

## 🧠 Prompt Engineering

O coração do projeto está no design cuidadoso do prompt para o GPT-4 Vision.

### Estratégias Utilizadas

#### 1. System Prompt com Persona Especializada
```
Você é um especialista em segurança de aplicações com 15 anos de experiência
em modelagem de ameaças usando a metodologia STRIDE...
```

#### 2. Few-Shot Examples
Exemplos concretos de ameaças por categoria são fornecidos para calibrar o modelo.

#### 3. Output Schema Enforcement
```
Retorne EXCLUSIVAMENTE um JSON válido no seguinte esquema:
{"threats": [...], "architecture_summary": "..."}
```

#### 4. Chain-of-Thought para Análise
```
Para cada componente visível na imagem:
1. Identifique o tipo (serviço, banco de dados, fila, usuário)
2. Mapeie os fluxos de dados entre componentes
3. Para cada fluxo, aplique as 6 categorias STRIDE
4. Avalie probabilidade e impacto
```

#### 5. Contextual Grounding
O contexto fornecido pelo usuário é injetado no prompt para tornar a análise mais precisa.

---

## 📄 Exemplo de Resposta

Veja um exemplo completo de análise em [`docs/example_response.json`](docs/example_response.json).

---

## 🧪 Testes

```bash
# Instalar dependências de teste
pip install -r requirements-dev.txt

# Executar todos os testes
pytest tests/ -v

# Com cobertura
pytest tests/ --cov=app --cov-report=html

# Apenas testes unitários (sem Azure)
pytest tests/unit/ -v
```

---

## 🐳 Deploy com Docker

```bash
# Build
docker build -t stride-threat-api .

# Run
docker run -p 8000:8000 --env-file .env stride-threat-api

# Docker Compose (com nginx)
docker-compose up -d
```

---

## 📚 O que Aprendi

### Azure OpenAI e GPT-4 Vision
- Como provisionar e configurar um recurso Azure OpenAI no portal
- A diferença entre Azure OpenAI e a API pública da OpenAI (autenticação, endpoints, versionamento)
- Como enviar imagens codificadas em base64 para o modelo de visão
- Boas práticas de **prompt engineering** para análises estruturadas

### FastAPI e Design de APIs
- Criação de endpoints assíncronos com upload de arquivos multipart
- Validação de dados com **Pydantic v2**
- Documentação automática via OpenAPI/Swagger
- Estruturação de projetos FastAPI escaláveis

### Segurança — Metodologia STRIDE
- As 6 categorias de ameaças e como aplicá-las na prática
- Diferença entre **análise de ameaças** e **análise de vulnerabilidades**
- Como mapear ameaças para controles de segurança (OWASP, NIST)
- Integração de segurança no ciclo de desenvolvimento (DevSecOps)

### Prompt Engineering
- Técnicas de **few-shot prompting** para resultados consistentes
- **Output schema enforcement** para garantir JSON válido
- **Chain-of-thought** para análises complexas
- Uso de **system prompts** para definir persona e comportamento

---

## 📚 Referências

- [STRIDE Threat Model — Microsoft](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Azure OpenAI Quickstart](https://learn.microsoft.com/en-us/azure/ai-services/openai/quickstart)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [OWASP Threat Modeling](https://owasp.org/www-community/Threat_Modeling)
- [stride-demo — Repositório de referência DIO](https://github.com/digitalinnovationone/stride-demo)

---

## 📝 Licença

MIT © 2025
