"""
Security Checklist Application - Seed Data
Initial categories and security checks
"""
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import Category, Check, Severity, User, UserRole
from app.auth import get_password_hash
from app.config import settings
import logging

logger = logging.getLogger(__name__)


async def seed_database(db: AsyncSession):
    """Seed the database with initial data"""
    
    # Check if already seeded
    result = await db.execute(select(Category).limit(1))
    if result.scalar_one_or_none():
        logger.info("Database already seeded, skipping...")
        return
    
    logger.info("Seeding database...")
    
    # Create admin user
    admin_exists = await db.execute(select(User).where(User.username == settings.ADMIN_USERNAME))
    if not admin_exists.scalar_one_or_none():
        admin_user = User(
            username=settings.ADMIN_USERNAME,
            email=settings.ADMIN_EMAIL,
            password_hash=get_password_hash(settings.ADMIN_PASSWORD),
            role=UserRole.ADMIN,
            is_active=True
        )
        db.add(admin_user)
        logger.info(f"Admin user '{settings.ADMIN_USERNAME}' created")
    
    # Create categories
    categories_data = get_seed_categories()
    category_map = {}
    
    for cat_data in categories_data:
        category = Category(**cat_data)
        db.add(category)
        category_map[cat_data["code"]] = category
    
    await db.flush()  # Get IDs
    
    # Create checks
    checks_data = get_seed_checks()
    for check_data in checks_data:
        cat_code = check_data.pop("category_code")
        category = category_map.get(cat_code)
        if category:
            # Convert severity string to enum
            severity_str = check_data.get("severity", "medium")
            check_data["severity"] = Severity(severity_str)
            check_data["category_id"] = category.id
            check = Check(**check_data)
            db.add(check)
    
    await db.commit()
    logger.info(f"Seeded {len(categories_data)} categories and {len(checks_data)} checks")


def get_seed_categories():
    """Return seed categories"""
    return [
        {
            "code": "EI",
            "name": "Exposição de Informação",
            "description": "Controles para prevenir vazamento de informações sensíveis",
            "order": 1,
            "icon": "fa-eye-slash"
        },
        {
            "code": "AC",
            "name": "Controle de Acesso",
            "description": "Controles de autorização e permissões",
            "order": 2,
            "icon": "fa-lock"
        },
        {
            "code": "VI",
            "name": "Validação de Entrada",
            "description": "Controles de validação e sanitização de dados",
            "order": 3,
            "icon": "fa-filter"
        },
        {
            "code": "AS",
            "name": "Autenticação e Sessão",
            "description": "Controles de autenticação e gerenciamento de sessão",
            "order": 4,
            "icon": "fa-user-shield"
        },
        {
            "code": "GS",
            "name": "Gestão de Segredos",
            "description": "Controles para proteção de credenciais e chaves",
            "order": 5,
            "icon": "fa-key"
        },
        {
            "code": "UA",
            "name": "Upload de Arquivos",
            "description": "Controles de segurança para upload de arquivos",
            "order": 6,
            "icon": "fa-upload"
        },
        {
            "code": "SA",
            "name": "Segurança em APIs",
            "description": "Controles específicos para APIs REST/GraphQL",
            "order": 7,
            "icon": "fa-code"
        },
        {
            "code": "CS",
            "name": "Configuração Segura",
            "description": "Hardening e configurações de segurança do servidor",
            "order": 8,
            "icon": "fa-cog"
        },
        {
            "code": "LM",
            "name": "Logs e Monitoramento",
            "description": "Controles de logging, auditoria e monitoramento",
            "order": 9,
            "icon": "fa-chart-line"
        },
        {
            "code": "TS",
            "name": "Testes de Segurança (SDLC)",
            "description": "Práticas de segurança no ciclo de desenvolvimento",
            "order": 10,
            "icon": "fa-vial"
        }
    ]


def get_seed_checks():
    """Return seed security checks"""
    return [
        # ============== EXPOSIÇÃO DE INFORMAÇÃO (EI) ==============
        {
            "category_code": "EI",
            "code": "EI-001",
            "title": "Headers de servidor não expõem versões",
            "description": "Verificar se headers HTTP como Server, X-Powered-By não revelam versões de software.",
            "severity": "low",
            "how_to_validate": """1. Faça uma requisição HTTP para a aplicação
2. Examine os headers de resposta
3. Verifique se existem headers como: Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version
4. Confirme que não revelam versões específicas de software""",
            "expected_evidence": "Screenshot ou log dos headers HTTP mostrando ausência de informações de versão",
            "recommendations": """- Remova ou mascare o header Server
- Remova headers X-Powered-By
- Configure o servidor web para não expor versões
- No Apache: ServerTokens Prod, ServerSignature Off
- No Nginx: server_tokens off;""",
            "mapping_owasp_asvs": "14.3.3",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-200",
            "has_automated_test": True,
            "test_type": "header_check",
            "test_config": {"check_headers": ["Server", "X-Powered-By", "X-AspNet-Version"]},
            "order": 1
        },
        {
            "category_code": "EI",
            "code": "EI-002",
            "title": "Mensagens de erro não expõem detalhes internos",
            "description": "Verificar se erros da aplicação não revelam stack traces, queries SQL, paths do servidor.",
            "severity": "medium",
            "how_to_validate": """1. Provoque erros na aplicação (404, 500, inputs inválidos)
2. Observe as mensagens de erro retornadas
3. Verifique se não contêm: stack traces, nomes de arquivos, queries SQL, paths do servidor
4. Confirme que erros são genéricos para o usuário""",
            "expected_evidence": "Screenshots de páginas de erro mostrando mensagens genéricas",
            "recommendations": """- Configure páginas de erro customizadas
- Desabilite modo debug em produção
- Log erros detalhados server-side, não client-side
- Use try/catch apropriados""",
            "mapping_owasp_asvs": "7.4.1",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-209",
            "has_automated_test": True,
            "test_type": "error_handling",
            "test_config": {},
            "order": 2
        },
        {
            "category_code": "EI",
            "code": "EI-003",
            "title": "Diretórios sensíveis não estão acessíveis",
            "description": "Verificar se diretórios como .git, .svn, backup, admin não estão expostos publicamente.",
            "severity": "high",
            "how_to_validate": """1. Tente acessar: /.git/config, /.svn/entries, /backup/, /admin/
2. Verifique se retornam 403 ou 404
3. Confirme que não há listagem de diretórios habilitada
4. Teste endpoints comuns de administração""",
            "expected_evidence": "Log de requisições mostrando 403/404 para paths sensíveis",
            "recommendations": """- Bloqueie acesso a .git, .svn, .env via servidor web
- Desabilite directory listing
- Remova arquivos de backup do servidor
- Use .htaccess ou configuração nginx para bloquear""",
            "mapping_owasp_asvs": "14.3.2",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-538",
            "has_automated_test": True,
            "test_type": "endpoint_check",
            "test_config": {},
            "order": 3
        },
        {
            "category_code": "EI",
            "code": "EI-004",
            "title": "Comentários HTML não contêm informações sensíveis",
            "description": "Verificar se o código-fonte HTML não contém comentários com senhas, TODOs sensíveis, ou informações internas.",
            "severity": "low",
            "how_to_validate": """1. Visualize o código-fonte das páginas principais
2. Busque por comentários HTML <!-- -->
3. Verifique se não contêm: credenciais, endpoints internos, TODOs de segurança
4. Revise também arquivos JavaScript""",
            "expected_evidence": "Revisão do código-fonte mostrando ausência de comentários sensíveis",
            "recommendations": """- Remova comentários de código em produção
- Use minificação de HTML/JS
- Implemente revisão de código antes do deploy
- Automatize verificação no CI/CD""",
            "mapping_owasp_asvs": "14.3.1",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-615",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "EI",
            "code": "EI-005",
            "title": "APIs não retornam dados excessivos",
            "description": "Verificar se APIs retornam apenas os campos necessários, sem expor dados sensíveis.",
            "severity": "medium",
            "how_to_validate": """1. Analise respostas de APIs da aplicação
2. Verifique se contêm apenas campos necessários
3. Confirme que dados como senhas, tokens internos não são retornados
4. Verifique paginação para evitar dump de dados""",
            "expected_evidence": "Exemplos de respostas de API mostrando campos apropriados",
            "recommendations": """- Implemente DTOs/Serializers específicos
- Nunca retorne objetos de banco diretamente
- Use campos explícitos em respostas
- Implemente paginação e limites""",
            "mapping_owasp_asvs": "13.1.3",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-213",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== CONTROLE DE ACESSO (AC) ==============
        {
            "category_code": "AC",
            "code": "AC-001",
            "title": "Autorização verificada em todas as requisições",
            "description": "Verificar se cada endpoint/recurso valida as permissões do usuário.",
            "severity": "critical",
            "how_to_validate": """1. Identifique recursos que requerem autorização
2. Tente acessar recursos de outros usuários (IDOR)
3. Tente acessar funcionalidades administrativas como usuário comum
4. Verifique se autorização é server-side""",
            "expected_evidence": "Testes mostrando bloqueio de acesso não autorizado",
            "recommendations": """- Implemente autorização em cada controller/endpoint
- Use middleware de autorização
- Valide ownership de recursos
- Nunca confie em dados do cliente para autorização""",
            "mapping_owasp_asvs": "4.1.1",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-862",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "AC",
            "code": "AC-002",
            "title": "Princípio do menor privilégio aplicado",
            "description": "Verificar se usuários têm apenas as permissões mínimas necessárias.",
            "severity": "high",
            "how_to_validate": """1. Revise a matriz de permissões/roles
2. Verifique se roles têm escopo adequado
3. Confirme que novos usuários têm permissões mínimas
4. Verifique segregação de funções""",
            "expected_evidence": "Documentação da matriz de roles e permissões",
            "recommendations": """- Defina roles com permissões granulares
- Implemente RBAC ou ABAC
- Revise permissões periodicamente
- Documente matriz de acesso""",
            "mapping_owasp_asvs": "4.1.3",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-269",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "AC",
            "code": "AC-003",
            "title": "Referências diretas a objetos protegidas (IDOR)",
            "description": "Verificar se IDs de recursos não podem ser manipulados para acessar dados de outros usuários.",
            "severity": "critical",
            "how_to_validate": """1. Identifique endpoints que usam IDs de recursos (ex: /api/users/123)
2. Tente alterar IDs para acessar recursos de outros usuários
3. Verifique se o backend valida ownership
4. Teste com IDs sequenciais e UUIDs""",
            "expected_evidence": "Testes mostrando que alteração de IDs retorna 403/404",
            "recommendations": """- Sempre valide ownership no backend
- Use UUIDs em vez de IDs sequenciais
- Implemente verificação de permissão por recurso
- Nunca exponha IDs internos diretamente""",
            "mapping_owasp_asvs": "4.2.1",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-639",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "AC",
            "code": "AC-004",
            "title": "Funções administrativas restritas",
            "description": "Verificar se funcionalidades administrativas são acessíveis apenas para administradores.",
            "severity": "critical",
            "how_to_validate": """1. Identifique URLs/endpoints administrativos
2. Tente acessar como usuário comum
3. Tente manipular roles no request
4. Verifique proteção server-side""",
            "expected_evidence": "Testes mostrando bloqueio de acesso admin para usuários comuns",
            "recommendations": """- Implemente verificação de role em endpoints admin
- Use decorators/middleware específicos
- Separe rotas administrativas
- Implemente MFA para admins""",
            "mapping_owasp_asvs": "4.1.2",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-285",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "AC",
            "code": "AC-005",
            "title": "Rate limiting implementado",
            "description": "Verificar se existe limitação de taxa de requisições para prevenir abusos.",
            "severity": "medium",
            "how_to_validate": """1. Faça múltiplas requisições rápidas a um endpoint
2. Verifique se recebe resposta 429 após limite
3. Confirme headers de rate limit (X-RateLimit-*)
4. Teste em endpoints críticos (login, API)""",
            "expected_evidence": "Demonstração de resposta 429 após exceder limite",
            "recommendations": """- Implemente rate limiting por IP/usuário
- Use headers X-RateLimit-Limit, X-RateLimit-Remaining
- Configure limites diferentes por endpoint
- Considere usar Redis para rate limiting distribuído""",
            "mapping_owasp_asvs": "13.2.1",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-770",
            "has_automated_test": True,
            "test_type": "rate_limit_check",
            "test_config": {"num_requests": 20},
            "order": 5
        },
        
        # ============== VALIDAÇÃO DE ENTRADA (VI) ==============
        {
            "category_code": "VI",
            "code": "VI-001",
            "title": "Proteção contra XSS implementada",
            "description": "Verificar se dados de usuário são sanitizados antes de exibição.",
            "severity": "high",
            "how_to_validate": """1. Identifique campos que exibem dados de usuário
2. Insira payloads de teste como: <script>alert(1)</script>, <img onerror=alert(1)>
3. Verifique se são escapados na exibição
4. Teste em diferentes contextos (HTML, JS, atributos)""",
            "expected_evidence": "Demonstração de escape correto de caracteres especiais",
            "recommendations": """- Use encoding de saída apropriado (HTML entities)
- Implemente Content-Security-Policy
- Use frameworks com auto-escape
- Sanitize HTML se necessário (DOMPurify)""",
            "mapping_owasp_asvs": "5.3.3",
            "mapping_owasp_top10": "A03:2021",
            "mapping_cwe": "CWE-79",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "VI",
            "code": "VI-002",
            "title": "Proteção contra SQL Injection",
            "description": "Verificar se queries SQL usam prepared statements ou ORM.",
            "severity": "critical",
            "how_to_validate": """1. Revise código que interage com banco de dados
2. Confirme uso de prepared statements/parameterized queries
3. Verifique que não há concatenação de strings em queries
4. Teste inputs com caracteres especiais SQL""",
            "expected_evidence": "Revisão de código mostrando uso de prepared statements",
            "recommendations": """- Use SEMPRE prepared statements
- Utilize ORM (SQLAlchemy, Sequelize, etc)
- Nunca concatene inputs em queries
- Implemente validação de tipos""",
            "mapping_owasp_asvs": "5.3.4",
            "mapping_owasp_top10": "A03:2021",
            "mapping_cwe": "CWE-89",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "VI",
            "code": "VI-003",
            "title": "Validação de entrada server-side",
            "description": "Verificar se toda validação de dados é feita também no servidor.",
            "severity": "high",
            "how_to_validate": """1. Identifique validações client-side
2. Bypass validações JS enviando requisição direta
3. Confirme que servidor valida todos os campos
4. Teste limites, tipos e formatos""",
            "expected_evidence": "Testes mostrando validação server-side funcionando",
            "recommendations": """- Nunca confie apenas em validação client-side
- Valide tipo, formato, tamanho e range
- Use schemas de validação (Pydantic, Joi)
- Retorne erros claros mas não verbosos""",
            "mapping_owasp_asvs": "5.1.1",
            "mapping_owasp_top10": "A03:2021",
            "mapping_cwe": "CWE-20",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "VI",
            "code": "VI-004",
            "title": "Proteção contra CSRF implementada",
            "description": "Verificar se operações sensíveis estão protegidas contra CSRF.",
            "severity": "high",
            "how_to_validate": """1. Identifique forms/endpoints que alteram dados
2. Verifique presença de token CSRF
3. Tente submeter form sem token ou com token inválido
4. Confirme que SameSite cookie está configurado""",
            "expected_evidence": "Demonstração de tokens CSRF em forms e rejeição de requisições inválidas",
            "recommendations": """- Implemente tokens CSRF em todas as operações de escrita
- Use SameSite=Strict ou Lax em cookies
- Verifique Origin/Referer header
- Use framework com proteção CSRF nativa""",
            "mapping_owasp_asvs": "4.2.2",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-352",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "VI",
            "code": "VI-005",
            "title": "Content-Type validado em requisições",
            "description": "Verificar se o servidor valida Content-Type de requisições.",
            "severity": "medium",
            "how_to_validate": """1. Envie requisição POST com Content-Type incorreto
2. Verifique se servidor rejeita ou processa incorretamente
3. Teste JSON endpoint com Content-Type: text/plain
4. Confirme parsing estrito""",
            "expected_evidence": "Demonstração de rejeição de Content-Type inválido",
            "recommendations": """- Valide Content-Type em cada endpoint
- Rejeite requisições com tipo inesperado
- Configure parsers apenas para tipos necessários
- Use middleware de validação""",
            "mapping_owasp_asvs": "13.2.3",
            "mapping_owasp_top10": "A03:2021",
            "mapping_cwe": "CWE-436",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== AUTENTICAÇÃO E SESSÃO (AS) ==============
        {
            "category_code": "AS",
            "code": "AS-001",
            "title": "Senhas armazenadas com hash seguro",
            "description": "Verificar se senhas são armazenadas com algoritmo seguro (bcrypt/Argon2).",
            "severity": "critical",
            "how_to_validate": """1. Revise código de cadastro/alteração de senha
2. Confirme uso de bcrypt, Argon2 ou scrypt
3. Verifique cost factor adequado (bcrypt >= 10)
4. Confirme que senhas nunca são logadas""",
            "expected_evidence": "Código mostrando uso de biblioteca de hash seguro",
            "recommendations": """- Use Argon2id ou bcrypt
- Configure cost factor alto (bcrypt >= 12)
- Nunca use MD5, SHA1 ou SHA256 sozinho
- Gere salt único por senha""",
            "mapping_owasp_asvs": "2.4.1",
            "mapping_owasp_top10": "A02:2021",
            "mapping_cwe": "CWE-916",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "AS",
            "code": "AS-002",
            "title": "Cookies de sessão seguros",
            "description": "Verificar se cookies de sessão têm flags Secure, HttpOnly e SameSite.",
            "severity": "high",
            "how_to_validate": """1. Autentique na aplicação
2. Examine cookies no navegador
3. Verifique flags: Secure, HttpOnly, SameSite
4. Confirme que cookie é transmitido apenas via HTTPS""",
            "expected_evidence": "Screenshot mostrando configuração segura dos cookies",
            "recommendations": """- Configure Secure flag (HTTPS only)
- Configure HttpOnly (previne acesso JS)
- Configure SameSite=Strict ou Lax
- Use prefixo __Host- ou __Secure-""",
            "mapping_owasp_asvs": "3.4.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-614",
            "has_automated_test": True,
            "test_type": "cookie_check",
            "test_config": {},
            "order": 2
        },
        {
            "category_code": "AS",
            "code": "AS-003",
            "title": "Timeout de sessão implementado",
            "description": "Verificar se sessões expiram após período de inatividade.",
            "severity": "medium",
            "how_to_validate": """1. Autentique na aplicação
2. Deixe sessão inativa pelo período configurado
3. Tente realizar ação que requer autenticação
4. Confirme que sessão expirou""",
            "expected_evidence": "Demonstração de expiração de sessão após inatividade",
            "recommendations": """- Configure timeout de 15-30 minutos para inatividade
- Implemente timeout absoluto (ex: 8 horas)
- Ofereça opção de logout
- Invalide sessão server-side""",
            "mapping_owasp_asvs": "3.3.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-613",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "AS",
            "code": "AS-004",
            "title": "Proteção contra brute force no login",
            "description": "Verificar se existe proteção contra tentativas repetidas de login.",
            "severity": "high",
            "how_to_validate": """1. Tente múltiplos logins inválidos seguidos
2. Verifique se conta é bloqueada ou rate limited
3. Confirme que CAPTCHA é exibido após tentativas
4. Verifique logs de tentativas falhas""",
            "expected_evidence": "Demonstração de bloqueio/CAPTCHA após tentativas falhas",
            "recommendations": """- Implemente bloqueio progressivo (1min, 5min, 30min)
- Use CAPTCHA após 3-5 tentativas falhas
- Implemente rate limiting por IP
- Log todas as tentativas de login""",
            "mapping_owasp_asvs": "2.2.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-307",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "AS",
            "code": "AS-005",
            "title": "Renovação de sessão após login",
            "description": "Verificar se ID de sessão é regenerado após autenticação bem-sucedida.",
            "severity": "medium",
            "how_to_validate": """1. Anote o session ID antes do login
2. Realize o login
3. Compare o session ID após login
4. Confirme que ID foi alterado""",
            "expected_evidence": "Demonstração de mudança de session ID após login",
            "recommendations": """- Regenere session ID após login
- Regenere após mudança de privilégio
- Invalide sessão antiga completamente
- Use biblioteca de sessão do framework""",
            "mapping_owasp_asvs": "3.2.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-384",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== GESTÃO DE SEGREDOS (GS) ==============
        {
            "category_code": "GS",
            "code": "GS-001",
            "title": "Credenciais não estão no código-fonte",
            "description": "Verificar se senhas, chaves API e tokens não estão hardcoded no código.",
            "severity": "critical",
            "how_to_validate": """1. Busque no código por padrões: password=, api_key=, secret=
2. Revise arquivos de configuração
3. Verifique histórico do git
4. Use ferramenta de detecção de segredos""",
            "expected_evidence": "Scan de código mostrando ausência de segredos hardcoded",
            "recommendations": """- Use variáveis de ambiente
- Use vault de segredos (HashiCorp Vault, AWS Secrets Manager)
- Adicione arquivos sensíveis ao .gitignore
- Use pre-commit hooks para detectar segredos""",
            "mapping_owasp_asvs": "2.10.4",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-798",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "GS",
            "code": "GS-002",
            "title": "Variáveis de ambiente para configuração sensível",
            "description": "Verificar se configurações sensíveis são carregadas de variáveis de ambiente.",
            "severity": "high",
            "how_to_validate": """1. Revise como a aplicação carrega configurações
2. Confirme uso de .env ou variáveis de ambiente
3. Verifique que .env não está no repositório
4. Confirme que valores padrão não são sensíveis""",
            "expected_evidence": "Código mostrando carregamento de configuração via env vars",
            "recommendations": """- Use python-dotenv, dotenv ou similar
- Nunca commite .env no repositório
- Documente variáveis necessárias em .env.example
- Use diferentes .env por ambiente""",
            "mapping_owasp_asvs": "2.10.3",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-260",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "GS",
            "code": "GS-003",
            "title": "Chaves de criptografia adequadamente protegidas",
            "description": "Verificar se chaves de criptografia são armazenadas de forma segura.",
            "severity": "critical",
            "how_to_validate": """1. Identifique onde chaves de criptografia são armazenadas
2. Verifique permissões de acesso aos arquivos
3. Confirme que não estão no código-fonte
4. Verifique rotação de chaves""",
            "expected_evidence": "Documentação do processo de gestão de chaves",
            "recommendations": """- Use HSM ou serviço de KMS
- Armazene chaves fora do código
- Implemente rotação periódica
- Limite acesso às chaves""",
            "mapping_owasp_asvs": "6.4.1",
            "mapping_owasp_top10": "A02:2021",
            "mapping_cwe": "CWE-321",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "GS",
            "code": "GS-004",
            "title": "Tokens de API com escopo limitado",
            "description": "Verificar se tokens de API têm permissões mínimas necessárias.",
            "severity": "medium",
            "how_to_validate": """1. Identifique tokens de API utilizados
2. Verifique as permissões de cada token
3. Confirme que seguem princípio do menor privilégio
4. Verifique expiração dos tokens""",
            "expected_evidence": "Lista de tokens e suas permissões documentadas",
            "recommendations": """- Crie tokens com escopo específico
- Implemente expiração de tokens
- Rotacione tokens periodicamente
- Log uso de tokens""",
            "mapping_owasp_asvs": "2.10.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-269",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "GS",
            "code": "GS-005",
            "title": "Arquivos .env no .gitignore",
            "description": "Verificar se arquivos de configuração sensíveis estão no .gitignore.",
            "severity": "high",
            "how_to_validate": """1. Examine o arquivo .gitignore
2. Confirme que .env, *.key, *.pem estão listados
3. Verifique histórico do git por commits de arquivos sensíveis
4. Confirme que .env.example existe sem valores reais""",
            "expected_evidence": "Conteúdo do .gitignore mostrando exclusões apropriadas",
            "recommendations": """- Adicione ao .gitignore: .env, *.key, *.pem, secrets/
- Use git-secrets ou similar
- Revise histórico com BFG ou git filter-branch se necessário
- Implemente pre-commit hooks""",
            "mapping_owasp_asvs": "2.10.4",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-540",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== UPLOAD DE ARQUIVOS (UA) ==============
        {
            "category_code": "UA",
            "code": "UA-001",
            "title": "Validação de tipo de arquivo",
            "description": "Verificar se uploads validam extensão E magic bytes do arquivo.",
            "severity": "high",
            "how_to_validate": """1. Tente fazer upload de arquivo com extensão permitida mas conteúdo diferente
2. Tente upload de arquivo executável renomeado
3. Verifique se validação é server-side
4. Confirme verificação de magic bytes""",
            "expected_evidence": "Demonstração de rejeição de arquivos com tipo incorreto",
            "recommendations": """- Valide extensão E magic bytes
- Use bibliotecas como python-magic
- Mantenha whitelist de tipos permitidos
- Nunca confie apenas na extensão""",
            "mapping_owasp_asvs": "12.1.1",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-434",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "UA",
            "code": "UA-002",
            "title": "Limite de tamanho de upload",
            "description": "Verificar se existe limite de tamanho para arquivos enviados.",
            "severity": "medium",
            "how_to_validate": """1. Tente fazer upload de arquivo grande (100MB+)
2. Verifique se servidor rejeita antes de processar
3. Confirme configuração de limite no servidor
4. Teste limite por endpoint se aplicável""",
            "expected_evidence": "Demonstração de rejeição de arquivo acima do limite",
            "recommendations": """- Configure limite no servidor web (nginx, apache)
- Configure limite na aplicação
- Retorne erro claro para o usuário
- Considere uploads em chunks para arquivos grandes""",
            "mapping_owasp_asvs": "12.1.3",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-400",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "UA",
            "code": "UA-003",
            "title": "Arquivos armazenados fora do webroot",
            "description": "Verificar se arquivos enviados são salvos fora do diretório público.",
            "severity": "high",
            "how_to_validate": """1. Faça upload de um arquivo
2. Verifique onde é armazenado no servidor
3. Confirme que não está acessível diretamente via URL
4. Verifique se é servido por endpoint controlado""",
            "expected_evidence": "Demonstração de armazenamento seguro de uploads",
            "recommendations": """- Armazene uploads fora do document root
- Use endpoint para servir arquivos com validação
- Gere nomes de arquivo aleatórios
- Considere usar storage externo (S3)""",
            "mapping_owasp_asvs": "12.1.2",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-434",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "UA",
            "code": "UA-004",
            "title": "Proteção contra path traversal",
            "description": "Verificar se nomes de arquivo são sanitizados contra path traversal.",
            "severity": "critical",
            "how_to_validate": """1. Tente upload com nome: ../../../etc/passwd
2. Tente upload com nome: ....//....//file.txt
3. Verifique se caracteres especiais são removidos
4. Confirme que path final é validado""",
            "expected_evidence": "Demonstração de sanitização de nome de arquivo",
            "recommendations": """- Use apenas o basename do arquivo
- Gere nomes aleatórios (UUID)
- Valide path final não escapa do diretório
- Use secure_filename() ou equivalente""",
            "mapping_owasp_asvs": "12.3.1",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-22",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "UA",
            "code": "UA-005",
            "title": "Scan de malware em uploads",
            "description": "Verificar se arquivos enviados são escaneados contra malware.",
            "severity": "medium",
            "how_to_validate": """1. Verifique se existe integração com antivírus
2. Confirme que scan é feito antes de disponibilizar arquivo
3. Teste com arquivo EICAR (teste seguro)
4. Verifique quarentena de arquivos suspeitos""",
            "expected_evidence": "Documentação de integração com antivírus/scan",
            "recommendations": """- Integre com ClamAV ou serviço similar
- Escaneie antes de disponibilizar arquivo
- Implemente quarentena para suspeitos
- Log todos os uploads""",
            "mapping_owasp_asvs": "12.2.1",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-434",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== SEGURANÇA EM APIS (SA) ==============
        {
            "category_code": "SA",
            "code": "SA-001",
            "title": "Autenticação em todos os endpoints",
            "description": "Verificar se todos os endpoints de API requerem autenticação apropriada.",
            "severity": "critical",
            "how_to_validate": """1. Liste todos os endpoints da API
2. Tente acessar cada um sem autenticação
3. Verifique se retornam 401 quando apropriado
4. Confirme que endpoints públicos são intencionais""",
            "expected_evidence": "Lista de endpoints com requisitos de autenticação",
            "recommendations": """- Use middleware global de autenticação
- Whitelist apenas endpoints públicos explícitos
- Documente requisitos de auth por endpoint
- Use OpenAPI/Swagger com security schemas""",
            "mapping_owasp_asvs": "13.1.1",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-306",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "SA",
            "code": "SA-002",
            "title": "CORS configurado corretamente",
            "description": "Verificar se política CORS não permite origens arbitrárias.",
            "severity": "high",
            "how_to_validate": """1. Envie requisição com Origin: https://evil.com
2. Verifique header Access-Control-Allow-Origin na resposta
3. Confirme que não reflete origem arbitrária
4. Verifique configuração de credentials""",
            "expected_evidence": "Demonstração de CORS rejeitando origens não autorizadas",
            "recommendations": """- Configure whitelist de origens permitidas
- Nunca use ACAO: * com credentials
- Não reflita Origin header dinamicamente
- Valide Origin server-side""",
            "mapping_owasp_asvs": "14.5.3",
            "mapping_owasp_top10": "A01:2021",
            "mapping_cwe": "CWE-942",
            "has_automated_test": True,
            "test_type": "cors_check",
            "test_config": {},
            "order": 2
        },
        {
            "category_code": "SA",
            "code": "SA-003",
            "title": "Versionamento de API implementado",
            "description": "Verificar se API possui versionamento para controle de mudanças.",
            "severity": "low",
            "how_to_validate": """1. Verifique URLs da API por padrão de versão (/v1/, /v2/)
2. Ou verifique header Accept-Version ou similar
3. Confirme que versões antigas são deprecadas
4. Verifique documentação de mudanças""",
            "expected_evidence": "Documentação de versionamento da API",
            "recommendations": """- Use versionamento na URL (/api/v1/) ou header
- Documente ciclo de vida de versões
- Deprecie versões antigas gradualmente
- Notifique clientes sobre mudanças""",
            "mapping_owasp_asvs": "13.1.2",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-1059",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "SA",
            "code": "SA-004",
            "title": "Validação de schema em requisições",
            "description": "Verificar se API valida schema/formato de todas as requisições.",
            "severity": "high",
            "how_to_validate": """1. Envie requisição com campos extras
2. Envie requisição com tipos incorretos
3. Envie requisição com campos faltando
4. Verifique se erros são apropriados""",
            "expected_evidence": "Demonstração de validação de schema funcionando",
            "recommendations": """- Use schemas de validação (JSON Schema, Pydantic)
- Valide todos os campos de entrada
- Rejeite campos desconhecidos
- Retorne erros claros de validação""",
            "mapping_owasp_asvs": "13.2.2",
            "mapping_owasp_top10": "A03:2021",
            "mapping_cwe": "CWE-20",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "SA",
            "code": "SA-005",
            "title": "Documentação de API atualizada",
            "description": "Verificar se documentação da API (OpenAPI/Swagger) está atualizada.",
            "severity": "low",
            "how_to_validate": """1. Acesse documentação da API
2. Compare endpoints documentados com implementados
3. Verifique se schemas de request/response estão corretos
4. Confirme que exemplos funcionam""",
            "expected_evidence": "Screenshot da documentação OpenAPI/Swagger",
            "recommendations": """- Gere documentação automaticamente do código
- Use annotations/decorators para documentar
- Mantenha exemplos funcionais
- Versione documentação junto com API""",
            "mapping_owasp_asvs": "13.1.5",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-1059",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== CONFIGURAÇÃO SEGURA (CS) ==============
        {
            "category_code": "CS",
            "code": "CS-001",
            "title": "HTTPS habilitado e forçado",
            "description": "Verificar se toda comunicação é via HTTPS com redirect de HTTP.",
            "severity": "critical",
            "how_to_validate": """1. Acesse aplicação via HTTP
2. Verifique se redireciona para HTTPS
3. Verifique header HSTS na resposta HTTPS
4. Confirme que conteúdo misto não existe""",
            "expected_evidence": "Demonstração de redirect HTTP->HTTPS e header HSTS",
            "recommendations": """- Configure redirect HTTP->HTTPS no servidor
- Implemente HSTS com max-age alto
- Considere HSTS preload
- Verifique conteúdo misto""",
            "mapping_owasp_asvs": "9.1.1",
            "mapping_owasp_top10": "A02:2021",
            "mapping_cwe": "CWE-319",
            "has_automated_test": True,
            "test_type": "tls_check",
            "test_config": {},
            "order": 1
        },
        {
            "category_code": "CS",
            "code": "CS-002",
            "title": "Headers de segurança configurados",
            "description": "Verificar presença de headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options.",
            "severity": "medium",
            "how_to_validate": """1. Faça requisição à aplicação
2. Examine headers de resposta
3. Verifique: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
4. Confirme valores apropriados""",
            "expected_evidence": "Lista de headers de segurança presentes na resposta",
            "recommendations": """- Strict-Transport-Security: max-age=31536000; includeSubDomains
- Content-Security-Policy: configure policy restritiva
- X-Frame-Options: DENY ou SAMEORIGIN
- X-Content-Type-Options: nosniff""",
            "mapping_owasp_asvs": "14.4.1",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-693",
            "has_automated_test": True,
            "test_type": "header_check",
            "test_config": {},
            "order": 2
        },
        {
            "category_code": "CS",
            "code": "CS-003",
            "title": "Modo debug desabilitado em produção",
            "description": "Verificar se modo debug está desabilitado em ambiente de produção.",
            "severity": "high",
            "how_to_validate": """1. Verifique configuração de debug no ambiente
2. Provoque um erro e verifique resposta
3. Confirme que não há stack traces expostos
4. Verifique que endpoints de debug não existem""",
            "expected_evidence": "Configuração mostrando debug=false em produção",
            "recommendations": """- Desabilite DEBUG em produção
- Use variáveis de ambiente para controlar
- Remova endpoints de debug
- Configure error handling customizado""",
            "mapping_owasp_asvs": "14.3.1",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-489",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "CS",
            "code": "CS-004",
            "title": "Métodos HTTP desnecessários desabilitados",
            "description": "Verificar se métodos como TRACE, TRACK estão desabilitados.",
            "severity": "low",
            "how_to_validate": """1. Teste método TRACE no servidor
2. Teste método TRACK no servidor
3. Verifique se retornam 405 ou 501
4. Confirme que apenas métodos necessários estão habilitados""",
            "expected_evidence": "Demonstração de rejeição de métodos TRACE/TRACK",
            "recommendations": """- Desabilite TRACE e TRACK no servidor web
- Configure apenas métodos necessários por endpoint
- Use 405 Method Not Allowed para métodos não suportados
- Documente métodos permitidos por endpoint""",
            "mapping_owasp_asvs": "14.5.1",
            "mapping_owasp_top10": "A05:2021",
            "mapping_cwe": "CWE-749",
            "has_automated_test": True,
            "test_type": "http_methods",
            "test_config": {},
            "order": 4
        },
        {
            "category_code": "CS",
            "code": "CS-005",
            "title": "Dependências atualizadas",
            "description": "Verificar se dependências não possuem vulnerabilidades conhecidas.",
            "severity": "high",
            "how_to_validate": """1. Execute scanner de dependências (npm audit, pip-audit, etc)
2. Verifique relatório de vulnerabilidades
3. Confirme que não há vulnerabilidades críticas/altas
4. Verifique política de atualização""",
            "expected_evidence": "Relatório de scanner de dependências sem vulns críticas",
            "recommendations": """- Execute scans regularmente (CI/CD)
- Atualize dependências vulneráveis
- Use Dependabot ou Renovate
- Mantenha inventário de dependências (SBOM)""",
            "mapping_owasp_asvs": "14.2.1",
            "mapping_owasp_top10": "A06:2021",
            "mapping_cwe": "CWE-1035",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== LOGS E MONITORAMENTO (LM) ==============
        {
            "category_code": "LM",
            "code": "LM-001",
            "title": "Eventos de segurança são logados",
            "description": "Verificar se tentativas de login, falhas de auth, e acessos negados são logados.",
            "severity": "high",
            "how_to_validate": """1. Realize tentativa de login inválido
2. Tente acessar recurso sem permissão
3. Verifique se eventos foram registrados nos logs
4. Confirme que logs têm informação suficiente""",
            "expected_evidence": "Exemplos de logs de eventos de segurança",
            "recommendations": """- Log todos os eventos de autenticação
- Log acessos negados (403)
- Log mudanças de permissão
- Inclua: timestamp, user, IP, ação, resultado""",
            "mapping_owasp_asvs": "7.1.1",
            "mapping_owasp_top10": "A09:2021",
            "mapping_cwe": "CWE-778",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "LM",
            "code": "LM-002",
            "title": "Logs não contêm dados sensíveis",
            "description": "Verificar se logs não registram senhas, tokens, ou dados pessoais sensíveis.",
            "severity": "high",
            "how_to_validate": """1. Revise configuração de logging
2. Examine amostras de logs
3. Confirme que senhas e tokens são mascarados
4. Verifique conformidade com LGPD/GDPR""",
            "expected_evidence": "Amostra de logs mostrando dados mascarados",
            "recommendations": """- Nunca log senhas ou tokens completos
- Mascare dados sensíveis (CPF, cartão)
- Use log levels apropriados
- Implemente retenção de logs""",
            "mapping_owasp_asvs": "7.1.2",
            "mapping_owasp_top10": "A09:2021",
            "mapping_cwe": "CWE-532",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "LM",
            "code": "LM-003",
            "title": "Logs protegidos contra tampering",
            "description": "Verificar se logs são protegidos contra modificação não autorizada.",
            "severity": "medium",
            "how_to_validate": """1. Verifique permissões de arquivos de log
2. Confirme que logs são enviados para servidor central
3. Verifique integridade dos logs
4. Confirme backup de logs""",
            "expected_evidence": "Documentação de proteção e centralização de logs",
            "recommendations": """- Envie logs para servidor central (SIEM)
- Use permissões restritivas em arquivos
- Considere assinatura de logs
- Implemente backup imutável""",
            "mapping_owasp_asvs": "7.3.1",
            "mapping_owasp_top10": "A09:2021",
            "mapping_cwe": "CWE-117",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "LM",
            "code": "LM-004",
            "title": "Alertas configurados para eventos críticos",
            "description": "Verificar se existem alertas para eventos de segurança críticos.",
            "severity": "medium",
            "how_to_validate": """1. Verifique configuração de alertas
2. Confirme que múltiplas falhas de login geram alerta
3. Verifique alertas para erros 500 excessivos
4. Confirme canal de notificação (email, Slack, etc)""",
            "expected_evidence": "Configuração de alertas e exemplo de notificação",
            "recommendations": """- Configure alertas para: múltiplas falhas de login, erros 500, acessos admin
- Use threshold apropriado para evitar fadiga
- Configure múltiplos canais de alerta
- Documente procedimento de resposta""",
            "mapping_owasp_asvs": "7.4.1",
            "mapping_owasp_top10": "A09:2021",
            "mapping_cwe": "CWE-778",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "LM",
            "code": "LM-005",
            "title": "Retenção de logs adequada",
            "description": "Verificar se logs são retidos pelo período necessário (compliance, investigação).",
            "severity": "low",
            "how_to_validate": """1. Verifique política de retenção de logs
2. Confirme período de retenção (mínimo 90 dias recomendado)
3. Verifique processo de rotação
4. Confirme conformidade com requisitos legais""",
            "expected_evidence": "Documentação de política de retenção",
            "recommendations": """- Defina período de retenção baseado em requisitos
- Implemente rotação automática
- Archive logs antigos para storage barato
- Considere requisitos legais (LGPD)""",
            "mapping_owasp_asvs": "7.3.4",
            "mapping_owasp_top10": "A09:2021",
            "mapping_cwe": "CWE-779",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        },
        
        # ============== TESTES DE SEGURANÇA SDLC (TS) ==============
        {
            "category_code": "TS",
            "code": "TS-001",
            "title": "SAST integrado no CI/CD",
            "description": "Verificar se análise estática de código (SAST) está integrada no pipeline.",
            "severity": "medium",
            "how_to_validate": """1. Verifique configuração do CI/CD
2. Confirme presença de ferramenta SAST
3. Verifique se build falha com vulnerabilidades críticas
4. Revise últimos relatórios""",
            "expected_evidence": "Screenshot do CI/CD mostrando stage de SAST",
            "recommendations": """- Integre Semgrep, SonarQube, ou similar
- Configure para falhar build em vulns críticas
- Revise findings regularmente
- Mantenha regras customizadas""",
            "mapping_owasp_asvs": "14.2.3",
            "mapping_owasp_top10": "A06:2021",
            "mapping_cwe": "CWE-1035",
            "has_automated_test": False,
            "test_type": None,
            "order": 1
        },
        {
            "category_code": "TS",
            "code": "TS-002",
            "title": "Scan de dependências vulneráveis",
            "description": "Verificar se há scan automático de dependências com vulnerabilidades conhecidas.",
            "severity": "high",
            "how_to_validate": """1. Verifique se npm audit, pip-audit ou similar está no CI
2. Confirme que PR/MR é bloqueado com vulns críticas
3. Verifique Dependabot ou similar configurado
4. Revise últimos alertas""",
            "expected_evidence": "Configuração de scan de dependências no CI",
            "recommendations": """- Use npm audit, pip-audit, OWASP Dependency-Check
- Configure Dependabot ou Renovate
- Bloqueie PRs com vulnerabilidades críticas
- Mantenha inventário de dependências""",
            "mapping_owasp_asvs": "14.2.1",
            "mapping_owasp_top10": "A06:2021",
            "mapping_cwe": "CWE-1035",
            "has_automated_test": False,
            "test_type": None,
            "order": 2
        },
        {
            "category_code": "TS",
            "code": "TS-003",
            "title": "Scan de secrets no código",
            "description": "Verificar se há detecção de secrets commitados no código.",
            "severity": "high",
            "how_to_validate": """1. Verifique se git-secrets, truffleHog ou similar está configurado
2. Confirme que há pre-commit hook
3. Verifique scan no CI/CD
4. Teste commitando um secret fake""",
            "expected_evidence": "Configuração de scan de secrets",
            "recommendations": """- Use git-secrets, truffleHog, ou Gitleaks
- Configure pre-commit hooks
- Escaneie histórico do repositório
- Integre no CI/CD""",
            "mapping_owasp_asvs": "2.10.4",
            "mapping_owasp_top10": "A07:2021",
            "mapping_cwe": "CWE-798",
            "has_automated_test": False,
            "test_type": None,
            "order": 3
        },
        {
            "category_code": "TS",
            "code": "TS-004",
            "title": "Revisão de código inclui segurança",
            "description": "Verificar se code review inclui checklist de segurança.",
            "severity": "medium",
            "how_to_validate": """1. Verifique processo de code review
2. Confirme que há checklist de segurança
3. Verifique se há reviewer com conhecimento em segurança
4. Revise PRs recentes por comentários de segurança""",
            "expected_evidence": "Checklist de segurança para code review",
            "recommendations": """- Crie checklist de segurança para PRs
- Treine desenvolvedores em segurança
- Use labels de segurança em PRs sensíveis
- Exija aprovação de security champion""",
            "mapping_owasp_asvs": "1.1.1",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-1059",
            "has_automated_test": False,
            "test_type": None,
            "order": 4
        },
        {
            "category_code": "TS",
            "code": "TS-005",
            "title": "Pentest periódico realizado",
            "description": "Verificar se pentests são realizados periodicamente.",
            "severity": "medium",
            "how_to_validate": """1. Verifique histórico de pentests
2. Confirme frequência (mínimo anual)
3. Verifique que findings foram remediados
4. Confirme escopo adequado""",
            "expected_evidence": "Relatório de pentest recente (sanitizado)",
            "recommendations": """- Realize pentest ao menos anualmente
- Contrate empresa especializada
- Remedie todos os findings críticos/altos
- Reteste após remediação""",
            "mapping_owasp_asvs": "1.1.3",
            "mapping_owasp_top10": "A04:2021",
            "mapping_cwe": "CWE-1059",
            "has_automated_test": False,
            "test_type": None,
            "order": 5
        }
    ]


def get_seed_application():
    """Return seed application for demo"""
    return {
        "name": "Aplicação Demo",
        "description": "Aplicação de exemplo para demonstrar o sistema de checklist de segurança.",
        "environment": "dev",
        "base_url": "https://example.com",
        "tags": "demo,exemplo,teste",
        "responsible": "Time de Segurança",
        "scope_urls": "https://example.com\nhttps://api.example.com",
        "scope_endpoints": "/api/v1/*\n/admin/*\n/auth/*",
        "scope_credentials_hint": "Usar usuário de teste: testuser (solicitar senha ao time)",
        "scope_notes": "Aplicação de demonstração. Não contém dados reais."
    }
