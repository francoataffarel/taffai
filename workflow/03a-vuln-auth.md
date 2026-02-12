# Fase 3a: Análise de Vulnerabilidades — Autenticação (Auth)
## Target: {{TARGET}}

> Baseado em: Shannon `vuln-auth.txt`
> Input: `deliverables/02_recon.md`, `deliverables/01_pre_recon.md`
> Output: `deliverables/03a_vuln_auth.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Especialista em análise de autenticação. White-box code audit + live testing.
Missão: encontrar ONDE a aplicação falha em responder "Você é quem diz ser?"

## Escopo
Apenas vulnerabilidades exploráveis externamente via {{TARGET}}.

## Metodologia: Checklist de Análise

### 1. Transport & Caching
- [ ] HTTPS enforced? Redirect HTTP→HTTPS?
- [ ] HSTS header presente?
- [ ] Tokens/senhas em URLs (query strings)?
- [ ] Cache-Control em respostas de auth?
- **Se falhou → classify:** `transport_exposure`

### 2. Rate Limiting
- [ ] Rate limit no login? (testar 10+ requests rápidos)
- [ ] Rate limit no registro?
- [ ] Rate limit no reset de senha?
- [ ] Account lockout após tentativas falhas?
- **Se falhou → classify:** `abuse_defenses_missing` → brute_force

### 3. Session Management
- [ ] Cookie flags: HttpOnly? Secure? SameSite?
- [ ] Session ID entropia (é UUID? sequencial?)
- [ ] Session timeout configurado?
- [ ] Logout invalida a sessão no server-side?
- **Se falhou → classify:** `session_management_flaw`

### 4. Token Properties
- [ ] JWT? Se sim: algoritmo? secret bruta-forcável?
- [ ] Token expira? TTL razoável?
- [ ] Token é invalidado no logout?
- [ ] Tokens logados em algum lugar?
- **Se falhou → classify:** `token_management_issue`

### 5. Session Fixation
- [ ] Session ID muda após login? (comparar antes/depois)
- **Se falhou → classify:** `login_flow_logic` → session_fixation

### 6. Password & Account Policy
- [ ] Credenciais default no código/fixtures?
- [ ] Password policy enforced server-side?
- [ ] Senhas armazenadas com hash (bcrypt, argon2)?
- **Se falhou → classify:** `weak_credentials`

### 7. Login/Signup Responses
- [ ] Mensagens de erro genéricas? (sem user enumeration)
- [ ] Auth state refletido em URLs/redirects?
- **Se falhou → classify:** `login_flow_logic` → account_enumeration

### 8. Recovery & Logout
- [ ] Reset token é de uso único?
- [ ] Reset token expira?
- [ ] Logout limpa todas as sessões?
- **Se falhou → classify:** `reset_recovery_flaw`

### 9. SSO/OAuth (se aplicável)
- [ ] Validação de `state` parameter?
- [ ] Validação de `nonce`?
- [ ] Callback endpoint validado?
- **Se falhou → classify:** `oauth_flow_issue`

## Critérios de Confiança
- **High:** falha direta e determinística, evidência de código/config
- **Medium:** falha provável mas com incerteza (controle upstream possível)
- **Low:** plausível mas não verificado

## Formato do Deliverable → `deliverables/03a_vuln_auth.md`

```markdown
# Authentication Analysis Report

## 1. Executive Summary
## 2. Dominant Vulnerability Patterns
## 3. Strategic Intelligence for Exploitation
## 4. Secure by Design: Validated Components
| Component | Endpoint | Defense | Verdict |
## 5. Constraints and Blind Spots
```

## Fila de Exploração
Para cada vulnerabilidade encontrada, documentar:
```json
{
  "ID": "AUTH-VULN-XX",
  "vulnerability_type": "tipo",
  "source_endpoint": "METHOD /path",
  "missing_defense": "descrição",
  "exploitation_hypothesis": "o que o atacante consegue",
  "suggested_exploit_technique": "técnica",
  "confidence": "High|Medium|Low"
}
```
