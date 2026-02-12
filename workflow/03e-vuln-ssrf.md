# Fase 3e: Análise de Vulnerabilidades — SSRF
## Target: {{TARGET}}

> Baseado em: Shannon `vuln-ssrf.txt`
> Input: `deliverables/02_recon.md` (seção 11: SSRF Vectors)
> Output: `deliverables/03e_vuln_ssrf.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Especialista em SSRF. Análise de como inputs influenciam requests outbound do servidor.
Missão: encontrar onde input do usuário controla destino de requests server-side.

## Metodologia

### 1. Identificar HTTP Client Usage
Para cada endpoint que aceita URLs/callbacks/webhooks:
- [ ] Traçar input → HTTP client (requests, urllib, axios, fetch, HttpClient)
- [ ] Endpoints que fazem: URL fetch, image processing, webhook, API proxy, file download
- **Se input chega no HTTP client → classify:** `URL_manipulation`

### 2. Validação de Protocolo/Scheme
- [ ] Apenas https:// e http:// permitidos?
- [ ] file://, ftp://, gopher://, dict://, ldap:// bloqueados?
- [ ] Allowlist vs blocklist? (blocklist é insuficiente)
- **Se falhou → classify:** `url_manipulation` → protocol_abuse

### 3. Validação de Hostname/IP
- [ ] IPs internos bloqueados? (127.0.0.1, 10.x, 172.16-31.x, 192.168.x)
- [ ] DNS rebinding protegido? (resolver DNS antes de validar?)
- [ ] IPv6 equivalents bloqueados? (::1, ::ffff:127.0.0.1)
- [ ] URL encoding bypasses? (%31%32%37%2e%30%2e%30%2e%31)
- **Se falhou → classify:** `URL_manipulation` → internal_service_access

### 4. Restrição de Porta
- [ ] Apenas portas padrão? (80, 443)
- [ ] Port scanning possível via SSRF?
- **Se falhou → classify:** `service_discovery` → port_scanning

### 5. Validação e Parsing de URL
- [ ] URL parseada corretamente? (bypasses com @, #, ?)
- [ ] Double encoding funciona?
- [ ] Redirects seguidos automaticamente? (open redirect chain)
- **Se falhou → classify:** `redirect_abuse`

### 6. Headers e Request Modification
- [ ] Headers sensíveis stripped em proxy? (Authorization, Cookie)
- [ ] Header injection via URL params?
- **Se falhou → classify:** `api_proxy_bypass` → credential_theft

### 7. Response Handling
- [ ] Erro vaza info interna?
- [ ] Conteúdo da resposta retorna ao usuário? (blind vs non-blind)
- **Se falhou → classify:** `file_fetch_abuse` → data_exfiltration

## Categorias de SSRF Sinks
- HTTP(S) Clients (requests, urllib, fetch, axios)
- Raw Sockets
- URL Openers / File Includes (file_get_contents, fopen)
- Redirect handlers
- Headless browsers (Puppeteer, Playwright)
- Media processors (ImageMagick, wkhtmltopdf)
- Link preview / unfurlers
- Webhook handlers
- SSO/OIDC discovery / JWKS fetchers
- Cloud metadata helpers

## False Positives
- Não assumir segurança só por firewall — verificar app layer
- Timeout ≠ SSRF confirmado (precisa de evidência adicional)

## Fila de Exploração
```json
{
  "ID": "SSRF-VULN-XX",
  "vulnerability_type": "URL_Manipulation|Redirect_Abuse|Webhook_Injection|API_Proxy_Bypass|File_Fetch_Abuse|Service_Discovery",
  "source_endpoint": "METHOD /path",
  "vulnerable_parameter": "nome do param",
  "vulnerable_code_location": "file:line",
  "missing_defense": "descrição",
  "exploitation_hypothesis": "o que o atacante consegue",
  "suggested_exploit_technique": "internal_service_access|cloud_metadata_retrieval|port_scanning|etc",
  "confidence": "High|Medium|Low",
  "notes": "detalhes relevantes"
}
```
