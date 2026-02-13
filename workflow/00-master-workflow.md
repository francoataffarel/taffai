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

### 4. Correlação obrigatória pós-LinPEAS
Após rodar LinPEAS e enumeração (4f), executar a fase de correlação (4g)
ANTES de tentar qualquer exploração de privesc. A correlação cruza OS +
PAM + polkit + D-Bus + sessão para identificar cadeias multi-step.
Extrair e usar `scripts/privesc_correlator.py` (embutido no 04g).
Ver `workflow/04g-privesc-correlation.md`.

### 5. NUNCA filtrar output de ferramentas com grep/head/tail inline
NÃO usar pipes como `| grep -E "^[0-9]{3}" | head -40` na mesma linha
de execução de ferramentas como feroxbuster, ffuf, gobuster, nmap, etc.
Isso causa perda de output, cancelamento prematuro e resultados incompletos.

**Correto:**
```bash
# Salvar output completo em arquivo, depois filtrar separadamente
feroxbuster -u http://TARGET -w wordlist.txt -o evidence/ferox_output.txt
# Depois:
cat evidence/ferox_output.txt | grep -E "^[0-9]{3}"
```

**ERRADO:**
```bash
# NÃO FAZER — output é perdido/truncado
feroxbuster -u http://TARGET -w wordlist.txt 2>&1 | grep -E "^[0-9]{3}" | head -40
```

### 6. Enumeração EXAUSTIVA de CVEs — não pegar o primeiro que "parece bom"
Antes de construir qualquer exploit, ENUMERAR TODOS os advisories do software-alvo.
Não parar no primeiro CVE que parece promissor. Criar uma tabela completa:

```markdown
| CVE | Tipo | Versões Afetadas | Pré-requisitos | Permissão do User | Viável? |
```

**Processo obrigatório:**
1. Buscar TODAS as advisories: `github.com/<vendor>/<product>/security/advisories`
2. Filtrar por versão: manter apenas os que afetam a versão do alvo
3. Cross-referenciar com permissões do user atual (ex: marcus não tem `settings.php`)
4. Priorizar por viabilidade real, NÃO por severidade CVSS
5. Só depois de ter a tabela completa, escolher qual explorar

**Motivo:** Na MonitorsFour, perdi tempo com CVE-2024-25641 (patcheado) e um CVE
fabricado (CVE-2025-66399), enquanto CVE-2025-24367 estava disponível e era viável.
A enumeração exaustiva teria mostrado isso em minutos.

### 7. NUNCA confiar em "memória" de CVEs — sempre validar com fetch real
O agente (LLM) pode INVENTAR/ALUCINAR números de CVE. TODA referência a CVE DEVE
ser validada com fetch real da fonte antes de qualquer ação.

**Processo obrigatório:**
```
1. Agente "lembra" de CVE-XXXX-YYYY? → NÃO USAR DIRETAMENTE
2. Fazer fetch de: https://nvd.nist.gov/vuln/detail/CVE-XXXX-YYYY
3. OU fetch de: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
4. Se o fetch retornar 404 ou conteúdo diferente → CVE é FABRICADO
5. Só após confirmação da fonte real → prosseguir com exploit
```

**Motivo:** CVE-2025-66399 foi inventado pelo agente. O número não existe em
nenhuma base. Tempo desperdiçado construindo exploit para vulnerabilidade fictícia.

### 8. Auto-pesquisa de CVEs para TODA versão descoberta
Toda vez que uma versão de software for identificada (via banner, fingerprint,
arquivo de configuração, output de comando, etc.), IMEDIATAMENTE abrir uma ação
em background (subagent) para pesquisar e validar CVEs para aquela versão.

**Processo obrigatório:**
1. Ao descobrir `Software X versão Y.Z` → registrar no inventário de versões
2. Lançar subagent de pesquisa: buscar CVEs no NVD, GitHub Advisories, e fontes
   específicas do vendor para `Software X` versões `<= Y.Z`
3. Subagent deve retornar tabela de triagem:
   ```
   | CVE | Severidade | Versões Afetadas | Tipo | Exploitável? |
   ```
4. Resultados são adicionados a `01b_cve_research.md` automaticamente
5. Versões sem CVEs conhecidos também devem ser registradas (para não re-pesquisar)

**Quando aplicar:**
- Nmap fingerprint (ex: `nginx/1.26.3`, `Microsoft HTTPAPI httpd 2.0`)
- Headers HTTP (ex: `X-Powered-By: PHP/8.3.27`)
- Páginas de versão (ex: Cacti "Version 1.2.28")
- Output de comandos no shell (ex: `docker --version`, `uname -r`)
- Arquivos de configuração (ex: `package.json`, `requirements.txt`)

**NÃO esperar acumular várias versões.** Cada versão descoberta dispara pesquisa
imediata. Usar subagents em paralelo quando múltiplas versões são descobertas
simultaneamente.

**Motivo:** Na MonitorsFour, o Docker Engine API estava exposto (CVE-2025-9074)
mas só foi descoberto depois que o user apontou que deveríamos pesquisar CVEs para
cada versão encontrada. A pesquisa automática teria identificado isso imediatamente
durante a enumeração pós-shell.

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
| 4g. Privesc Correlation | ⬜ Pendente | `privesc_correlation.md` |
| 5. Report | ⬜ Pendente | `05_report_executive.md` |
