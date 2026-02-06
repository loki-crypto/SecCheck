# 🔐 Security Checklist - DevSecOps Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.109+-green?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/OWASP-Compliant-orange?style=for-the-badge&logo=owasp&logoColor=white" alt="OWASP">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

Uma aplicação web completa para criar e executar **checklists de requisitos de segurança** em aplicações web, com testes automatizados e relatórios detalhados.

---

## 🚀 Funcionalidades

### ✅ Checklist de Segurança
- **10 categorias** de controles de segurança (baseado em OWASP)
- **50 verificações** pré-configuradas
- Mapeamento com **OWASP ASVS**, **OWASP Top 10** e **CWE**
- Status por verificação: Conforme, Parcial, Não Conforme, N/A
- Registro de evidências e anexos
- Histórico completo de alterações

### 🔬 Testes Automatizados
- Verificação de headers de segurança
- Validação de configuração TLS/SSL
- Testes de CORS
- Verificação de cookies seguros
- Análise de métodos HTTP habilitados
- Testes de rate limiting
- Verificação de endpoints sensíveis

### 📊 Relatórios e Dashboard
- Dashboard interativo com métricas em tempo real
- Relatórios por aplicação
- Exportação de dados
- Resumo executivo para gestão

### 👥 Gestão de Usuários
- Autenticação JWT segura
- Três papéis: **Admin**, **Auditor**, **Developer**
- Controle de acesso granular por função
- Página de configurações do usuário

---

## 📁 Estrutura do Projeto

```
devsecops/
├── main.py                 # Entrada da aplicação FastAPI
├── requirements.txt        # Dependências Python
├── .env                    # Configurações de ambiente
├── .env.example            # Exemplo de configuração
├── .gitignore
├── .dockerignore
├── README.md
├── Dockerfile
├── docker-compose.yml
└── app/
    ├── __init__.py
    ├── config.py           # Configurações (Pydantic Settings)
    ├── database.py         # Conexão SQLAlchemy async
    ├── models.py           # Modelos do banco de dados
    ├── schemas.py          # Schemas Pydantic para validação
    ├── auth.py             # Autenticação JWT + Rate Limiting
    ├── routes.py           # Rotas da API REST
    ├── seed_data.py        # Dados iniciais (categorias/checks)
    ├── test_executor.py    # Executor de testes de segurança
    ├── report_generator.py # Gerador de relatórios
    ├── static/             # Arquivos estáticos (CSS)
    │   └── styles.css
    └── templates/          # Templates Jinja2
        ├── base.html       # Layout base
        ├── login.html      # Página de login
        ├── dashboard.html  # Dashboard principal
        ├── applications.html # Gestão de aplicações
        ├── checklist.html  # Checklist de segurança
        ├── tests.html      # Testes automatizados
        ├── reports.html    # Relatórios
        ├── users.html      # Gestão de usuários (admin)
        ├── categories.html # Categorias de controles
        └── settings.html   # Configurações do usuário
```

---

## 🛠️ Instalação

### Pré-requisitos
- Python 3.10+ ou Docker
- SQLite (incluído no Python)

### 🐳 Com Docker (Recomendado)

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/security-checklist.git
cd security-checklist

# Execute com Docker Compose
docker compose up -d

# Acesse
http://localhost:8000
```

### 💻 Instalação Local

1. **Clone o repositório:**
```bash
git clone https://github.com/seu-usuario/security-checklist.git
cd security-checklist
```

2. **Crie um ambiente virtual:**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

3. **Instale as dependências:**
```bash
pip install -r requirements.txt
```

4. **Configure as variáveis de ambiente:**
```bash
cp .env.example .env
# Edite o .env e configure o SECRET_KEY
```

5. **Execute a aplicação:**
```bash
python main.py
```

6. **Acesse:**
```
http://localhost:8000
```

---

## 🔑 Credenciais Padrão

| Usuário | Senha | Papel |
|---------|-------|-------|
| `admin` | `admin123` | Administrador |

⚠️ **IMPORTANTE:** Altere a senha do admin imediatamente em produção!

---

## 📋 Categorias de Segurança

| Código | Categoria | Controles | Descrição |
|--------|-----------|-----------|-----------|
| **EI** | Exposição de Informação | 5 | Headers, mensagens de erro, diretórios |
| **AC** | Controle de Acesso | 5 | Autorização, IDOR, rate limiting |
| **VI** | Validação de Entrada | 5 | XSS, SQL Injection, CSRF |
| **AS** | Autenticação e Sessão | 5 | Senhas, cookies, sessões |
| **GS** | Gestão de Segredos | 5 | Credenciais, chaves, tokens |
| **UA** | Upload de Arquivos | 5 | Validação, armazenamento |
| **SA** | Segurança em APIs | 5 | Autenticação, CORS, versionamento |
| **CS** | Configuração Segura | 5 | HTTPS, headers, métodos HTTP |
| **LM** | Logs e Monitoramento | 5 | Auditoria, alertas, retenção |
| **TS** | Testes de Segurança | 5 | SAST, DAST, pentest |

---

## 🔌 API Endpoints

### 🔐 Autenticação
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/auth/login` | Login e obter token JWT |
| GET | `/api/auth/me` | Dados do usuário atual |
| POST | `/api/auth/change-password` | Alterar senha |

### 📱 Aplicações
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/applications` | Listar aplicações |
| POST | `/api/applications` | Criar aplicação |
| GET | `/api/applications/{id}` | Detalhes da aplicação |
| PUT | `/api/applications/{id}` | Atualizar aplicação |
| DELETE | `/api/applications/{id}` | Excluir aplicação |

### ✅ Checklist
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/categories` | Listar categorias |
| GET | `/api/checks` | Listar controles |
| GET | `/api/results/application/{id}` | Resultados por aplicação |
| POST | `/api/results` | Salvar resultado |

### 🔬 Testes Automatizados
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| POST | `/api/tests/execute` | Executar teste |
| GET | `/api/tests/recent` | Testes recentes |
| GET | `/api/tests/application/{id}` | Testes por aplicação |

### 📊 Relatórios
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/reports/summary/{id}` | Resumo da aplicação |
| GET | `/api/dashboard/stats` | Estatísticas do dashboard |

### 👥 Usuários (Admin)
| Método | Endpoint | Descrição |
|--------|----------|-----------|
| GET | `/api/users` | Listar usuários |
| POST | `/api/users` | Criar usuário |
| PUT | `/api/users/{id}` | Atualizar usuário |
| DELETE | `/api/users/{id}` | Excluir usuário |

---

## 🔒 Segurança da Aplicação

Esta aplicação foi desenvolvida seguindo boas práticas de segurança:

### 🛡️ Proteções Implementadas

- ✅ **Autenticação JWT** com tokens seguros e expiração configurável
- ✅ **Senhas com hash bcrypt** (nunca armazenadas em texto plano)
- ✅ **Rate limiting** para proteção contra brute force
- ✅ **Validação de entrada** com Pydantic schemas
- ✅ **Escape de output** para prevenção de XSS
- ✅ **CORS configurável** para controle de origens
- ✅ **Logs estruturados** em formato JSON para SIEM
- ✅ **Endpoints de documentação ocultos** em produção

### 🔑 SECRET_KEY Seguro

- Geração automática com `secrets.token_urlsafe(64)` (86 caracteres)
- Persistência em arquivo com permissões `0600` (apenas owner)
- Mantido entre reinicializações do container
- Nunca commitado no repositório (`.gitignore`)

### 🚫 Proteção Anti-SSRF

O executor de testes implementa validação rigorosa de URLs:

```python
# URLs bloqueadas automaticamente:
- localhost, 127.0.0.1, ::1
- Redes privadas (10.x, 172.16.x, 192.168.x)
- Link-local (169.254.x.x)
- Cloud metadata endpoints (169.254.169.254)
- Schemes não permitidos (apenas http/https)
- Hostnames que resolvem para IPs internos
```

### 📝 JSON Structured Logging

Logs estruturados para fácil integração com ferramentas de monitoramento:

```json
{
  "timestamp": "2026-02-06T19:15:21.418436Z",
  "level": "INFO",
  "logger": "root",
  "message": "Starting Security Checklist Application",
  "module": "main",
  "function": "lifespan",
  "line": 35
}
```

Campos extras suportados: `user_id`, `ip_address`, `request_id`, `action`, `duration_ms`

---

## 🧪 Testes Automatizados Disponíveis

Os testes são **seguros por design** - apenas verificam configurações, **não executam ataques**:

| Teste | Descrição |
|-------|-----------|
| **Header Check** | Verifica headers de segurança (X-Frame-Options, CSP, HSTS) |
| **HTTP Methods** | Valida métodos HTTP permitidos |
| **Cookie Check** | Analisa flags de segurança dos cookies (HttpOnly, Secure) |
| **TLS Check** | Verifica configuração HTTPS/TLS |
| **Endpoint Check** | Testa exposição de endpoints sensíveis |
| **CORS Check** | Valida configuração CORS |
| **Error Handling** | Verifica vazamento de informações em erros |
| **Rate Limit** | Testa existência de rate limiting |

---

## 🔧 Configuração

### Variáveis de Ambiente

```env
# Segurança (gerado automaticamente se não definido)
# SECRET_KEY=sua-chave-secreta-muito-segura-aqui

# Banco de dados
DATABASE_URL=sqlite+aiosqlite:///./data/security_checklist.db

# Servidor
HOST=0.0.0.0
PORT=8000
DEBUG=false

# CORS (JSON array)
CORS_ORIGINS=["http://localhost:8000","http://127.0.0.1:8000"]

# Logging
LOG_LEVEL=INFO
LOG_JSON_FORMAT=true
```

---

## 🐳 Docker

### Comandos úteis
```bash
# Subir containers
docker compose up -d

# Ver logs (formato JSON estruturado)
docker logs -f security-checklist

# Ver apenas logs JSON parseados
docker logs security-checklist 2>&1 | grep -E '^\{'

# Parar
docker compose down

# Rebuild completo
docker compose build --no-cache && docker compose up -d

# Verificar saúde
curl http://localhost:8000/health
```

### Volumes Persistentes

| Volume | Caminho | Descrição |
|--------|---------|-----------|
| `security_data` | `/app/data` | Banco SQLite + SECRET_KEY |
| `security_uploads` | `/app/uploads` | Arquivos enviados |

---

## 📄 Licença

Este projeto é distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## 🤝 Contribuição

Contribuições são bem-vindas! 

1. Faça um Fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

---

<p align="center">
  <strong>Desenvolvido para profissionais de DevSecOps e AppSec</strong> 🛡️
</p>

<p align="center">
  ⭐ Se este projeto te ajudou, considere dar uma estrela!
</p>
