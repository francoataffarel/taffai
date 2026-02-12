# Shannon-Adapted Pentest Workflow
## Target: {{TARGET}} ({{TARGET_IP}})

> Workflow adaptado do Shannon (KeygraphHQ) para uso local com Copilot.
> Sem APIs pagas — execução sequencial, um agente, ferramentas CLI.

---

## ⚠️ ANTES DE CADA FASE: Perguntar o Contexto

Antes de executar qualquer fase, o agente DEVE perguntar:

> **Qual é o contexto deste teste?**
> - **HTB/CTF:** Ambiente controlado. Sem DNS público, sem subfinder, sem scans de infra real. Foco em fuzzing local, análise manual, exploração direta.
> - **Real/Autorizado:** Engagement real com escopo definido. Todas as ferramentas disponíveis conforme autorização.

### Ferramentas por Contexto

| Ferramenta | HTB/CTF | Real |
|------------|---------|------|
| nmap | ✅ | ✅ |
| ffuf / gobuster | ✅ (dir/vhost) | ✅ |
| whatweb | ✅ (básico) | ✅ |
| curl | ✅ | ✅ |
| sqlmap | ✅ | ✅ (com cuidado) |
| subfinder | ❌ | ✅ |
| nikto | ❌ (ruidoso) | ✅ |
| nuclei | ⚠️ (opcional) | ✅ |
| burpsuite | ✅ | ✅ |
| hydra | ✅ | ✅ (dentro do escopo) |

---

## Sequência de Fases

```
Phase 1: PRE-RECON (Análise de código + scans externos)
    ↓
Phase 1b: CVE RESEARCH (Versão→CVE→Exploit→Teste)
    ↓
Phase 2: RECON (Mapeamento interativo da superfície de ataque)
    ↓
Phase 3: VULN ANALYSIS (5 especialistas em sequência)
    ├── 3a. Auth Analysis
    ├── 3b. Authz Analysis
    ├── 3c. Injection Analysis
    ├── 3d. XSS Analysis
    └── 3e. SSRF Analysis
    ↓
Phase 4: EXPLOITATION (5 especialistas em sequência)
    ├── 4a. Auth Exploit
    ├── 4b. Authz Exploit
    ├── 4c. Injection Exploit
    ├── 4d. XSS Exploit
    ├── 4e. SSRF Exploit
    └── 4f. Post-Shell Enum (OBRIGATÓRIO a cada novo shell/user)
    ↓
Phase 5: REPORT (Relatório executivo consolidado)
```

## Estrutura de Pastas

```
<project>/
├── nmap_scan.txt                # Scan inicial
├── deliverables/               # Relatórios de cada fase
│   ├── 01_pre_recon.md
│   ├── 01b_cve_research.md
│   ├── 02_recon.md
│   ├── 03a_vuln_auth.md
│   ├── 03b_vuln_authz.md
│   ├── 03c_vuln_injection.md
│   ├── 03d_vuln_xss.md
│   ├── 03e_vuln_ssrf.md
│   ├── 04a_exploit_auth.md
│   ├── 04b_exploit_authz.md
│   ├── 04c_exploit_injection.md
│   ├── 04d_exploit_xss.md
│   ├── 04e_exploit_ssrf.md
│   └── 05_report_executive.md
├── workflow/                   # Prompts e checklists por fase
├── scripts/                    # Scripts de automação (Python/Bash)
└── evidence/                   # Screenshots, responses, logs
```

## Como Usar

1. Abra o prompt da fase atual em `workflow/`
2. Me passe: "execute fase X" ou "vamos para fase X"
3. Eu sigo o checklist da fase, usando terminal + ferramentas
4. Ao final de cada fase, gero o deliverable em `deliverables/`
5. O deliverable alimenta a próxima fase

## ⚠️ Regras Invioláveis

### 1. linpeas/winpeas é OBRIGATÓRIO a cada novo acesso
A cada novo shell ou user obtido, rodar linpeas/winpeas ANTES de qualquer
enumeração manual ou tentativa de privesc. Ver `workflow/04f-post-shell-enum.md`.

### 2. CVE Research inclui pesquisa WEB
searchsploit é o começo, não o fim. Para CADA CVE encontrado, buscar na web
(NVD, SOCRadar, Qualys, oss-security, blogs) para entender cadeias e CVEs
companion. Ver `workflow/01b-cve-research.md`.

### 3. CVEs vêm em cadeias
Ao encontrar um CVE, SEMPRE verificar se há CVEs relacionados. Um CVE
isolado pode parecer "baixo impacto" mas combinado com outro = RCE/root.

## Status do Progresso

| Fase | Status | Deliverable |
|------|--------|-------------|
| 1. Pre-Recon | ⬜ Pendente | `01_pre_recon.md` |
| 1b. CVE Research | ⬜ Pendente | `01b_cve_research.md` |
| 2. Recon | ⬜ Pendente | `02_recon.md` |
| 3a. Vuln Auth | ⬜ Pendente | `03a_vuln_auth.md` |
| 3b. Vuln Authz | ⬜ Pendente | `03b_vuln_authz.md` |
| 3c. Vuln Injection | ⬜ Pendente | `03c_vuln_injection.md` |
| 3d. Vuln XSS | ⬜ Pendente | `03d_vuln_xss.md` |
| 3e. Vuln SSRF | ⬜ Pendente | `03e_vuln_ssrf.md` |
| 4a. Exploit Auth | ⬜ Pendente | `04a_exploit_auth.md` |
| 4b. Exploit Authz | ⬜ Pendente | `04b_exploit_authz.md` |
| 4c. Exploit Injection | ⬜ Pendente | `04c_exploit_injection.md` |
| 4d. Exploit XSS | ⬜ Pendente | `04d_exploit_xss.md` |
| 4e. Exploit SSRF | ⬜ Pendente | `04e_exploit_ssrf.md` |
| 4f. Post-Shell Enum | ⬜ Pendente | `evidence/linpeas_*.txt` |
| 5. Report | ⬜ Pendente | `05_report_executive.md` |
