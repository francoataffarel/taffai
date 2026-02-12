# Fase 3c: Análise de Vulnerabilidades — Injection (SQLi, CMDi, LFI, SSTI)
## Target: {{TARGET}}

> Baseado em: Shannon `vuln-injection.txt`
> Input: `deliverables/02_recon.md` (seção 9: Injection Sources)
> Output: `deliverables/03c_vuln_injection.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Especialista em injeção. Análise de fluxo source→sanitizer→sink.
Missão: provar que input não confiável alcança sinks perigosos sem defesa adequada.

## Tipos de Vulnerabilidade
- **SQLi:** input → query SQL (concatenação, sem prepared statements)
- **Command Injection:** input → exec/system/subprocess (shell=True)
- **LFI/Path Traversal:** input → file operations (read/include/require)
- **SSTI:** input → template render/compile
- **Deserialization:** input → pickle.loads/unserialize/readObject

## Metodologia: Taint Analysis (Source → Sink)

### Para cada input vector do recon:

#### 1. Criar Todo
- [ ] Listar cada source de injection do pre-recon/recon

#### 2. Traçar Data Flow Path
Para cada source:
- [ ] **A. Path completo:** source → transformações → sink
- [ ] **B. Sanitizações no caminho:** nome, file:line, tipo
- [ ] **C. Concatenações:** toda concat/format com dados tainted (flag pós-sanitização!)

#### 3. Detectar Sinks e Labeling
- SQL: `SQL-val | SQL-like | SQL-num | SQL-enum | SQL-ident`
- CMD: `CMD-argument | CMD-part-of-string`
- FILE: `FILE-path | FILE-include`
- TEMPLATE: `TEMPLATE-expression`
- DESERIALIZE: `DESERIALIZE-object`

#### 4. Avaliar Defesa vs Contexto
- [ ] Sanitização é apropriada para o tipo de slot?
- [ ] Prepared statements / parameter binding usados?
- [ ] Whitelist validation para identifiers?
- [ ] Alguma concatenação APÓS sanitização? (anula a defesa)

#### 5. Verdict
- **Vulnerable:** source→sink sem defesa adequada para o contexto
- **Safe:** defesa correta e context-appropriate

## Witness Payloads (para fase de exploit — NÃO executar agora)
- SQLi: `'` `"` `)` `;` `\` | `' AND 1=1--` | `' UNION SELECT NULL--`
- CMDi: `; ls` | `| whoami` | `` `id` `` | `$(cat /etc/passwd)`
- LFI: `../../../../etc/passwd` | `....//....//etc/passwd`
- SSTI: `{{7*7}}` | `${7*7}` | `<%= 7*7 %>`
- Deserialization: payloads específicos por linguagem

## False Positives a Evitar
- Prepared statements com parameter binding SÃO defesa suficiente
- Type casting para int/float É defesa (para SQL-num)
- Array-based command execution (shell=False) É seguro
- Normalização (lowercase, trim) NÃO é sanitização

## Fila de Exploração
```json
{
  "ID": "INJ-VULN-XX",
  "vulnerability_type": "SQLi|CommandInjection|LFI|SSTI|PathTraversal|Deserialization",
  "source": "param name & file:line",
  "path": "controller → fn → sink",
  "sink_call": "file:line & function",
  "slot_type": "SQL-val|CMD-argument|etc",
  "sanitization_observed": "nome & file:line",
  "mismatch_reason": "porque a defesa é insuficiente",
  "witness_payload": "payload mínimo",
  "confidence": "high|med|low"
}
```
