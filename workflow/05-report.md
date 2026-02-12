# Fase 5: Relatório Executivo
## Target: {{TARGET}}

> Baseado em: Shannon `report-executive.txt`
> Input: TODOS os deliverables anteriores
> Output: `deliverables/05_report_executive.md`

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina o formato e nível de detalhe do relatório.

## Papel
Report writer para liderança técnica (CTOs, CISOs, VPs de Eng).
Consolidar todos os findings em um relatório limpo e acionável.

## Processo

### 1. Ler Todos os Deliverables
- [ ] `01_pre_recon.md` — scan findings
- [ ] `02_recon.md` — attack surface
- [ ] `03a-03e` — análise de vulnerabilidades
- [ ] `04a-04e` — evidências de exploração

### 2. Gerar Relatório

```markdown
# Security Assessment Report

## Executive Summary
- Target: {{TARGET}} ({{TARGET_IP}})
- Assessment Date: {{DATA}}
- Scope: Auth, Authz, Injection, XSS, SSRF

## Summary by Vulnerability Type

**Authentication Vulnerabilities:**
[Resumo dos findings de auth]

**Authorization Vulnerabilities:**
[Resumo dos findings de authz]

**Injection Vulnerabilities:**
[Resumo dos findings de injection]

**XSS Vulnerabilities:**
[Resumo dos findings de XSS]

**SSRF Vulnerabilities:**
[Resumo dos findings de SSRF]

## Network Reconnaissance
- Open ports and exposed services
- Subdomains discovered
- Security headers / misconfigurations

## Exploitation Evidence
[Consolidar seções de "Successfully Exploited" de cada 04x]

## Recommendations
[Para cada finding explorado, recomendação de fix]
```

### 3. Regras de Limpeza
- MANTER: Successfully Exploited Vulnerabilities com IDs
- REMOVER: Potential/Theoretical, False Positives, Conclusions genéricas
- Preservar IDs e formatação exata dos findings

## Conclusão
Salvar em `deliverables/05_report_executive.md`
Anunciar: "ASSESSMENT COMPLETO"
