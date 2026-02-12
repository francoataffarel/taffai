# TAFFAI — Tactical Framework for AI-Assisted Infiltration

Framework de pentest adaptado do [Shannon (KeygraphHQ)](https://github.com/KeygraphHQ/shannon) para uso local com **GitHub Copilot** — sem APIs pagas, sem multi-agente, execução sequencial via CLI.

---

## Visão Geral

TAFFAI organiza um pentest em **5 fases sequenciais**, cada uma com checklist, metodologia e deliverable padronizados:

```
Phase 1:  PRE-RECON (Análise de código + scans externos)
    ↓
Phase 1b: CVE RESEARCH (Versão → CVE → Exploit → Teste)
    ↓
Phase 2:  RECON (Mapeamento interativo da superfície de ataque)
    ↓
Phase 3:  VULN ANALYSIS (5 especialistas em sequência)
    ├── 3a. Auth Analysis
    ├── 3b. Authz Analysis
    ├── 3c. Injection Analysis
    ├── 3d. XSS Analysis
    └── 3e. SSRF Analysis
    ↓
Phase 4:  EXPLOITATION (5 especialistas + pós-exploração)
    ├── 4a. Auth Exploit
    ├── 4b. Authz Exploit
    ├── 4c. Injection Exploit
    ├── 4d. XSS Exploit
    ├── 4e. SSRF Exploit
    ├── 4f. Post-Shell Enum (OBRIGATÓRIO a cada novo shell/user)
    └── 4g. Privesc Correlation (Correlação multi-vetor para escalação)
    ↓
Phase 5:  REPORT (Relatório executivo consolidado)
```

## Estrutura do Projeto

```
taffai/
├── README.md                        # Este arquivo
├── workflow/                        # Templates de cada fase (genéricos)
│   ├── 00-master-workflow.md        # Visão geral e tracker de progresso
│   ├── 01-pre-recon.md              # Fase 1: Reconhecimento externo + análise de código
│   ├── 01b-cve-research.md          # Fase 1b: CVE Research & Exploit Hunting
│   ├── 02-recon.md                  # Fase 2: Mapeamento interativo da superfície de ataque
│   ├── 03a-vuln-auth.md             # Fase 3a: Análise de autenticação
│   ├── 03b-vuln-authz.md            # Fase 3b: Análise de autorização
│   ├── 03c-vuln-injection.md        # Fase 3c: Análise de injeção (SQLi, CMDi, LFI, SSTI)
│   ├── 03d-vuln-xss.md              # Fase 3d: Análise de XSS
│   ├── 03e-vuln-ssrf.md             # Fase 3e: Análise de SSRF
│   ├── 04a-exploit-auth.md          # Fase 4a: Exploração de auth
│   ├── 04b-exploit-authz.md         # Fase 4b: Exploração de authz
│   ├── 04c-exploit-injection.md     # Fase 4c: Exploração de injection
│   ├── 04d-exploit-xss.md           # Fase 4d: Exploração de XSS
│   ├── 04e-exploit-ssrf.md          # Fase 4e: Exploração de SSRF
│   ├── 04f-post-shell-enum.md       # Fase 4f: Enumeração pós-shell (linpeas/winpeas)
│   ├── 04g-privesc-correlation.md   # Fase 4g: Correlação de privesc multi-vetor
│   └── 05-report.md                 # Fase 5: Relatório executivo consolidado
├── deliverables/                    # Relatórios gerados por fase (output)
├── scripts/                         # Scripts de automação (Python/Bash)
└── evidence/                        # Screenshots, responses, logs de prova
```

## Como Usar

### 1. Copiar para o projeto alvo

```bash
cp -r ~/taffai ~/engagements/<nome-do-alvo>/
```

### 2. Iniciar com o Copilot

Abra o VS Code na pasta do projeto e diga ao Copilot:

```
execute fase 1
```

O Copilot vai:
1. **Perguntar o contexto**: CTF ou Real/Autorizado
2. **Pedir o target**: hostname e IP (para substituir `{{TARGET}}` e `{{TARGET_IP}}`)
3. **Seguir o checklist** da fase, executando comandos no terminal
4. **Gerar o deliverable** em `deliverables/`

### 3. Avançar entre fases

```
execute fase 2
vamos para fase 3a
execute fase 4c
```

Cada fase lê o deliverable da fase anterior como input.

### 4. Pular fases (se necessário)

Se uma classe de vulnerabilidade não se aplica (ex: sem SSRF vectors), pule:

```
pular fase 3e, ir para 4a
```

## Placeholders

Os templates usam placeholders que são substituídos no momento da execução:

| Placeholder | Descrição | Exemplo |
|-------------|-----------|---------|
| `{{TARGET}}` | Hostname do alvo | `alvo.com` |
| `{{TARGET_IP}}` | IP do alvo | `10.10.x.x` |
| `{{DATA}}` | Data do assessment | `2026-02-12` |

**Não é necessário editar os arquivos manualmente** — o Copilot faz a substituição contextual durante a execução.

## Contexto CTF vs Real

Antes de cada fase, o framework pergunta se o contexto é **CTF** ou **Real**. Isso afeta:

| Ferramenta | CTF | Real |
|------------|-----|------|
| nmap | ✅ | ✅ |
| ffuf / gobuster | ✅ | ✅ |
| whatweb | ✅ | ✅ |
| curl | ✅ | ✅ |
| sqlmap | ✅ | ✅ (com cuidado) |
| hydra | ✅ | ✅ (dentro do escopo) |
| burpsuite | ✅ | ✅ |
| subfinder | ❌ | ✅ |
| nikto | ❌ | ✅ |
| nuclei | ⚠️ (opcional) | ✅ |

## Regras Invioláveis

1. **linpeas/winpeas é OBRIGATÓRIO** a cada novo shell ou user obtido — rodar ANTES de qualquer enumeração manual ou tentativa de privesc.
2. **CVE Research inclui pesquisa WEB** — searchsploit é o começo, não o fim. Buscar na web (NVD, SOCRadar, Qualys, oss-security, blogs) para entender cadeias e CVEs companion.
3. **CVEs vêm em cadeias** — ao encontrar um CVE, SEMPRE verificar se há CVEs relacionados. Um CVE isolado pode parecer baixo impacto mas combinado com outro = RCE/root.
4. **Correlação obrigatória pós-LinPEAS** — executar a fase 4g ANTES de tentar qualquer exploração de privesc.

## Metodologia (baseada no Shannon)

Cada fase de análise de vulnerabilidade segue uma metodologia específica:

- **Auth**: Checklist de 9 categorias (transport, rate limit, session, tokens, fixation, password, enumeration, recovery, SSO)
- **Authz**: Análise horizontal (IDOR), vertical (privilege escalation), contextual (workflow bypass)
- **Injection**: Taint analysis source→sanitizer→sink com slot labeling (SQL-val, CMD-argument, FILE-path, etc.)
- **XSS**: Backward taint sink→source com render context matching (HTML_BODY, JS_STRING, etc.)
- **SSRF**: Análise de URL manipulation, protocol abuse, DNS rebinding, redirect chains
- **Post-Shell**: Enumeração automatizada com linpeas/winpeas + enumeração manual de credenciais, processos, rede
- **Privesc Correlation**: Cruzamento multi-vetor (OS + PAM + polkit + D-Bus + sessão) para cadeias de escalação

Cada finding recebe um **ID único** (ex: `AUTH-VULN-01`, `INJ-VULN-03`) e a exploração requer **prova de impacto** (não basta identificar — precisa explorar até Nível 3+).

## Requisitos

- Linux (Kali, Parrot, ou qualquer distro com ferramentas de pentest)
- VS Code + GitHub Copilot
- Ferramentas CLI: `nmap`, `ffuf`, `gobuster`, `curl`, `whatweb`, `sqlmap`, `hydra`
- Wordlists: SecLists (`/usr/share/seclists/`)

## Créditos

- **Shannon** por [KeygraphHQ](https://github.com/KeygraphHQ/shannon) — framework original multi-agente
- Adaptação para uso local e single-agent por TAFFAI
