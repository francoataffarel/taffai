# Fase 1: PRE-RECON (Análise Externa + Código)
## Target: {{TARGET}} ({{TARGET_IP}})

> Baseado em: Shannon `pre-recon-code.txt`
> Objetivo: Criar baseline de inteligência técnica para todas as fases seguintes.

---

## Papel
Analista de segurança focado em reconhecimento externo e análise de código.
Perspectiva: atacante externo sem acesso interno.

## ⚠️ Contexto: Perguntar antes de executar
Antes de iniciar, confirmar: **HTB/CTF** ou **Real**?

## Ferramentas Disponíveis

### Sempre disponíveis
- `nmap` (já executado)
- `whatweb` (fingerprint de tecnologias — modo básico)
- `ffuf`, `gobuster` (enumeração de diretórios e vhosts)
- `curl` (inspeção manual de headers e respostas)
- Código-fonte (se aplicação é open source conhecida)

### Apenas em contexto Real (NÃO usar em HTB)
- `subfinder` (sem DNS público em lab)
- `nikto` (ruído desnecessário em CTF)
- Nuclei (scans agressivos)

## Checklist de Execução

### 1. Sintetizar Dados de Scan Existentes
- [ ] Revisar scan nmap existente (portas, serviços, versões)
- [ ] Documentar: serviços, versões e redirects encontrados
- [ ] Adicionar {{TARGET}} ao /etc/hosts (se necessário)

### 2. Fingerprint de Tecnologias
- [ ] `whatweb http://{{TARGET}}`
- [ ] `curl -sI http://{{TARGET}}` (headers de resposta)
- [ ] Identificar framework (PHP? Node? Python? Go?)
- [ ] Identificar CMS ou painel (WordPress? Joomla? Custom?)
- [ ] Verificar headers de segurança (CSP, X-Frame-Options, HSTS, etc.)

### 3. Enumeração de Subdomínios/Vhosts
- [ ] ~~`subfinder`~~ (❌ NÃO usar em HTB — sem DNS público)
- [ ] `ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://{{TARGET}} -H "Host: FUZZ.{{TARGET}}" -fs <tamanho_padrão>` (✅ vhost fuzzing funciona em HTB)
- [ ] Adicionar vhosts encontrados ao /etc/hosts

### 4. Enumeração de Diretórios e Endpoints

> ⚠️ **REGRA**: NUNCA filtrar output de feroxbuster/gobuster/ffuf com `| grep | head` inline.
> Sempre salvar em arquivo com `-o` e filtrar DEPOIS com `cat arquivo | grep`.

- [ ] `feroxbuster -u http://{{TARGET}} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -d 2 --auto-tune --no-state -o evidence/ferox_TARGET.txt`
- [ ] (alternativa) `gobuster dir -u http://{{TARGET}} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50 -o evidence/gobuster_TARGET.txt`
- [ ] `ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -u http://{{TARGET}}/FUZZ -mc 200,301,302,403`
- [ ] Procurar: /admin, /api, /login, /register, /robots.txt, /sitemap.xml, /.env

### 4b. Triagem de Endpoints Descobertos (OBRIGATÓRIO)

> Cada endpoint encontrado na enumeração DEVE ser investigado individualmente.
> O objetivo é mapear a lógica interna da aplicação e encontrar leaks.

**Regras de triagem:**

1. **Respostas pequenas (< 500 bytes) = provavelmente API**
   - Acessar com `curl -s` e ler o body completo
   - Respostas JSON com mensagens de erro (`{"error":"..."}`) são **information leaks** — revelam nomes de parâmetros, lógica interna, e fluxos de autenticação

2. **Quando uma resposta diz "Missing X parameter":**
   - O nome do parâmetro já foi revelado → testar via GET (`?param=test`) e POST (`-d "param=test"`)
   - Testar variações: `token`, `api_token`, `auth_token`, `key`, `id`, `session`
   - Comparar resposta de "missing" vs "invalid" → respostas diferentes confirmam que o parâmetro foi aceito

3. **Conectar endpoints ao fluxo de auth:**
   - Se existe `/login` + `/forgot-password` + `/user?token=X` → o token é provavelmente um reset token
   - Mapear: login → esqueci senha → token enviado por email → endpoint que valida token
   - Cada peça do fluxo pode ter vulnerabilidades (token previsível, IDOR, brute force)

4. **Respostas 405 (Method Not Allowed) = endpoint existe mas o método HTTP está errado**
   - Se GET retorna 405, testar POST, PUT, DELETE, PATCH
   - Se POST retorna 405, testar GET

**Checklist:**
- [ ] Listar todos os endpoints com status ≠ 404
- [ ] Acessar cada endpoint individualmente com `curl -s`
- [ ] Documentar respostas JSON com mensagens de erro (são leaks)
- [ ] Para cada "Missing X" → testar o parâmetro via GET e POST
- [ ] Mapear o fluxo completo de auth (login → reset → token → user)

### 5. Análise de Código (se disponível)
- [ ] Verificar se a aplicação é open source (GitHub)
- [ ] Se sim, analisar: rotas, controllers, middleware de auth
- [ ] Mapear endpoints de API documentados
- [ ] Identificar sinks perigosos (SQL, exec, template, file ops)

### 6. Infraestrutura e Segurança Operacional
- [ ] Identificar versões com CVEs conhecidos (verificar cada serviço do nmap)
- [ ] Verificar se há WAF (testar com payloads básicos)
- [ ] ~~`nikto`~~ (❌ NÃO usar em HTB — ruidoso e pouco útil em CTF)

## Formato do Deliverable

O relatório final deve ser salvo em `deliverables/01_pre_recon.md` com:

```markdown
# Pre-Recon Deliverable: {{TARGET}}

## 1. Executive Summary
Breve visão do alvo, stack tecnológico, componentes principais.

## 2. Architecture & Technology Stack
- Frontend: [framework, libs]
- Backend: [linguagem, framework]
- Infraestrutura: [servidor web, DB]
- Subdomínios: [lista]
- Portas/Serviços: [lista do nmap]

## 3. Authentication & Authorization
- Mecanismos de auth encontrados
- Endpoints de login/register/reset
- Session management (JWT? Cookie?)

## 4. Data Security & Storage
- Banco de dados identificado
- Schemas encontrados
- Dados sensíveis expostos

## 5. Attack Surface
- Endpoints descobertos (tabela)
- Parâmetros de input mapeados
- Upload de arquivos?
- APIs expostas?

## 6. Infrastructure & Security
- Headers de segurança presentes/ausentes
- WAF detectado?
- CVEs aplicáveis

## 7. Injection Sources
- SQL injection potenciais
- Command injection potenciais
- SSTI/LFI/RFI potenciais

## 8. Critical File Paths
- Arquivos de configuração
- Auth/Authz
- API/Routing
- Data Models

## 9. XSS Sinks
- DOM sinks
- Template rendering
- Reflected/Stored vectors

## 10. SSRF Sinks
- HTTP clients encontrados
- URL fetchers
- Webhook handlers
```

## Conclusão da Fase
Quando todos os itens do checklist estiverem marcados:
1. Gere o deliverable em `deliverables/01_pre_recon.md`
2. Anuncie: "PRE-RECON COMPLETO"
3. Prossiga para Fase 2 (Recon)
