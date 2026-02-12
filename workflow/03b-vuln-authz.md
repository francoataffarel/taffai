# Fase 3b: Análise de Vulnerabilidades — Autorização (Authz)
## Target: {{TARGET}}

> Baseado em: Shannon `vuln-authz.txt`
> Input: `deliverables/02_recon.md` (seção 8: Horizontal, Vertical, Context)
> Output: `deliverables/03b_vuln_authz.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Especialista em autorização. White-box audit de controles de acesso.
Missão: encontrar ONDE a aplicação falha em responder "Você tem permissão para fazer isso?"

## Metodologia

### 1. Análise Horizontal (IDOR)
Para cada endpoint com Object IDs no recon:
- [ ] Traçar path do ID até o banco de dados
- [ ] Verificar se há ownership check antes do side-effect
- [ ] Verificar se guard domina TODOS os code paths
- **Vulnerable:** side-effect alcançado antes de ownership check
- **Guarded:** ownership check domina o sink

### 2. Análise Vertical (Privilege Escalation)
Para cada endpoint de admin/privilégio no recon:
- [ ] Traçar path até o side-effect
- [ ] Verificar se há role/capability guard
- [ ] Guard executado ANTES do side-effect?
- [ ] Guard domina todos os code paths?
- **Vulnerable:** operação privilegiada sem role check
- **Guarded:** role check domina o sink

### 3. Análise Context/Workflow
Para cada workflow multi-step no recon:
- [ ] Cada step valida o estado do step anterior?
- [ ] Status flags/tokens de estado usados?
- [ ] Guard roda ANTES da mudança de estado?
- **Vulnerable:** step permite skip do estado anterior

### 4. Proof Obligations
- Finding é **guarded** se guard domina o sink
- Finding é **vulnerable** se side-effect é alcançado sem guard
- Guards APÓS o side-effect NÃO contam
- Checks apenas no UI (botões escondidos) NÃO contam

## False Positives a Evitar
- UI-only checks não são guards de autorização
- Estar logado ≠ ter ownership/role check
- Não assumir que framework provê authz automaticamente
- Verificar acesso indireto (via objetos relacionados)

## Formato do Deliverable → `deliverables/03b_vuln_authz.md`
Mesmo formato do Shannon: Executive Summary, Patterns, Strategic Intel, Secure Components, Blind Spots.

## Fila de Exploração
```json
{
  "ID": "AUTHZ-VULN-XX",
  "vulnerability_type": "Horizontal|Vertical|Context_Workflow",
  "endpoint": "METHOD /path",
  "vulnerable_code_location": "file:line",
  "role_context": "roles que triggeram",
  "guard_evidence": "missing/misplaced guard",
  "side_effect": "ação não autorizada possível",
  "reason": "explicação",
  "confidence": "High|Medium|Low",
  "minimal_witness": "sketch do exploit"
}
```
