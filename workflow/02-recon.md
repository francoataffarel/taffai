# Fase 2: RECON (Mapeamento Interativo da Superfície de Ataque)
## Target: {{TARGET}} ({{TARGET_IP}})

> Baseado em: Shannon `recon.txt`
> Input: `deliverables/01_pre_recon.md`
> Output: `deliverables/02_recon.md`

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Analista de reconhecimento e mapeamento de superfície de ataque.
Missão: criar mapa completo que alimente TODOS os 5 especialistas de vuln analysis.

## Escopo
Apenas componentes acessíveis via rede (HTTP/HTTPS na porta 80).
Fora de escopo: CLI tools, build scripts, dev servers locais.

## Ferramentas
- `curl` (inspeção de endpoints, headers, cookies)
- `ffuf` / `burpsuite` (fuzzing de parâmetros)
- Browser (navegação manual para mapear fluxos)
- `python3` (scripts de automação)

## Checklist de Execução

### 1. Sintetizar Dados do Pre-Recon
- [ ] Ler `deliverables/01_pre_recon.md` completo
- [ ] Listar tecnologias, subdomínios, portas, módulos de código encontrados

### 2. Exploração Interativa da Aplicação
- [ ] Navegar na aplicação (página principal, login, register)
- [ ] Mapear TODAS as funcionalidades visíveis:
  - [ ] Formulários de login
  - [ ] Registro de conta
  - [ ] Reset de senha
  - [ ] Painel de controle (dashboard)
  - [ ] Configurações de perfil
  - [ ] Funcionalidades administrativas
- [ ] Documentar processos multi-step (login → dashboard → ação)
- [ ] Observar requests no network tab / curl

### 3. Inventário de API/Endpoints
- [ ] Mapear TODOS os endpoints encontrados (método, path, parâmetros)
- [ ] Para cada endpoint documentar:
  - Método HTTP
  - Path
  - Parâmetros (query, body, headers)
  - Autenticação requerida (role)
  - Parâmetros com Object IDs (candidatos IDOR)

### 4. Mapeamento de Autenticação (para Auth specialist)
- [ ] Mecanismo de auth (session cookie? JWT? API key?)
- [ ] Fluxo completo de login (request/response)
- [ ] Fluxo de registro
- [ ] Fluxo de reset de senha
- [ ] Cookie flags (HttpOnly, Secure, SameSite)
- [ ] Headers de segurança na auth

### 5. Mapeamento de Autorização (para Authz specialist)
- [ ] Roles descobertos (user, admin, moderator, etc.)
- [ ] Endpoints que aceitam IDs de objetos (IDOR candidates)
- [ ] Endpoints de admin vs user
- [ ] Multi-tenancy? Isolamento de dados?

### 6. Mapeamento de Input Vectors (para Injection/XSS)
- [ ] TODOS os campos de input (formulários, search, comments)
- [ ] Parâmetros de URL que refletem na resposta
- [ ] Headers que a aplicação processa
- [ ] Upload de arquivos?
- [ ] APIs que aceitam JSON/XML body

### 7. Mapeamento de Request Outbound (para SSRF)
- [ ] Funcionalidades que buscam URLs externas
- [ ] Webhooks configuráveis
- [ ] Import de dados via URL
- [ ] Preview de links
- [ ] Integração com serviços externos

## Formato do Deliverable

Salvar em `deliverables/02_recon.md`:

```markdown
# Reconnaissance Deliverable: {{TARGET}}

## 0. How to Read This
Guia rápido para os especialistas.

## 1. Executive Summary
Visão geral da aplicação e componentes.

## 2. Technology & Service Map
- Frontend / Backend / Infra / Subdomínios / Portas

## 3. Entry Points
Tabela de TODOS os formulários, inputs, uploads.

## 4. API Endpoint Inventory
| Method | Path | Params | Auth Required | Role | Object IDs |
|--------|------|--------|---------------|------|------------|

## 5. Authentication Map
- Mecanismo, fluxos, cookies, tokens

## 6. Network & Interaction Map
### 6.1 Entities (componentes do sistema)
### 6.2 Entity Metadata
### 6.3 Flows (conexões entre entidades)
### 6.4 Guards (middleware, decorators, permission checks)

## 7. Role & Privilege Architecture
### 7.1 Discovered Roles
### 7.2 Role Hierarchy
### 7.3 Permission Matrix
### 7.4 Role-to-Code Mapping

## 8. Authorization Vulnerability Candidates
### Horizontal (IDOR candidates)
### Vertical (privilege escalation candidates)
### Context (workflow bypass candidates)

## 9. Injection Sources
- SQL injection, Command injection, LFI/RFI, SSTI, Deserialization

## 10. XSS Vectors
- Reflected, Stored, DOM-based candidates

## 11. SSRF Vectors
- URL fetchers, webhooks, API proxies
```

## Conclusão da Fase
1. Gere deliverable em `deliverables/02_recon.md`
2. Anuncie: "RECON COMPLETO"
3. Prossiga para Fase 3 (Vuln Analysis)
