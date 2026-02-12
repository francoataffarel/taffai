````markdown
# Fase 3f: Análise de Vulnerabilidades — IDOR (Insecure Direct Object Reference)
## Target: {{TARGET}}

> Input: `deliverables/02_recon.md` (endpoints com IDs, parâmetros numéricos/sequenciais)
> Output: `deliverables/03f_vuln_idor.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Em **Real/Autorizado**: limitar coleta de dados de outros usuários ao mínimo necessário para provar o bug. PII é responsabilidade do tester.
> Em **HTB/CTF**: pode iterar livremente para extrair tudo.

## Papel
Especialista em controle de acesso a objetos. Auditor de referências diretas.
Missão: encontrar ONDE a aplicação expõe objetos (arquivos, registros, recursos) via referências previsíveis sem validação de ownership.

---

## Conceito

IDOR ocorre quando a aplicação usa input do usuário (ID, filename, token) para acessar objetos diretamente sem verificar se o usuário tem permissão sobre aquele objeto.

**Dois sabores principais:**
1. **Referência direta a objetos de banco** — `?user_id=132355`, `/api/orders/42`
2. **Referência direta a arquivos estáticos** — `/download/7`, `/static/12144.txt`, `/uploads/report_003.pdf`

**Impacto:** horizontal priv-esc (acessar dados de outros users), vertical priv-esc (acessar dados de admin), data leak massivo.

---

## Metodologia

### 1. Identificar Superfície IDOR
Varrer todos os endpoints do recon buscando:
- [ ] IDs numéricos sequenciais em URLs (`/download/7`, `/user/3`, `/order/42`)
- [ ] IDs numéricos em parâmetros (`?id=7`, `?customer_number=132355`)
- [ ] Filenames previsíveis (`/static/12144.txt`, `/uploads/report_003.pdf`)
- [ ] UUIDs ou hashes (menos provável, mas testar se são previsíveis)
- [ ] IDs em corpos de requisição POST/PUT/PATCH
- [ ] IDs em headers customizados

**Fontes para encontrar IDs:**
- URLs visitadas durante recon
- Responses JSON (campos como `id`, `user_id`, `file_id`, `object_id`)
- Links em páginas HTML
- JavaScript client-side (hardcoded IDs, API calls)
- Cookies e tokens JWT (claims com IDs)

### 2. Análise de Previsibilidade
Para cada ID encontrado:
- [ ] É sequencial/incremental? (`1, 2, 3, ...`)
- [ ] É baseado em timestamp?
- [ ] É UUID v1 (previsível) vs v4 (random)?
- [ ] Pode ser enumerado via outra funcionalidade? (e.g., user listing expõe IDs)
- [ ] O range é pequeno o bastante para bruteforce?

**Indicadores de alta probabilidade:**
| Sinal | Risco |
|-------|-------|
| ID numérico sequencial em URL | 🔴 Alto |
| Filename com padrão incremental | 🔴 Alto |
| UUID v1 (time-based) | 🟡 Médio |
| Hash MD5/SHA de valor previsível | 🟡 Médio |
| UUID v4 (random, 128-bit) | 🟢 Baixo |
| Token HMAC assinado | 🟢 Baixo |

### 3. Análise de Controles de Acesso
Para cada endpoint com IDOR potencial:
- [ ] Requisição REQUER autenticação? (cookie, token, header)
- [ ] Se autenticado: trocar ID retorna dados de outro user?
- [ ] Se não autenticado: endpoint é público? (pior caso)
- [ ] Há rate limiting no endpoint?
- [ ] Há logging/alerting para acesso anômalo?
- [ ] Response varia entre "meu objeto" e "objeto de outro"?

**Checklist de guarda:**
```
Request → Auth Check → Ownership Check → Return Object
                ↑              ↑
           Presente?      Presente?
```
- **Vulnerable:** ownership check ausente ou apenas no frontend
- **Guarded:** ownership check server-side antes de retornar o objeto

### 4. Análise de Impacto por Tipo de Objeto
| Tipo de Objeto | Impacto se IDOR |
|----------------|-----------------|
| Dados pessoais (PII) | 🔴 Crítico |
| Credenciais / tokens | 🔴 Crítico |
| Capturas de rede (PCAP) | 🔴 Crítico (pode conter creds) |
| Arquivos financeiros | 🔴 Crítico |
| Configurações de conta | 🟡 Alto |
| Logs / relatórios | 🟡 Alto |
| Conteúdo público reindexado | 🟢 Baixo |

### 5. Mapeamento de Ranges
Antes de explorar, mapear o range de IDs válidos:
- [ ] Qual é o menor ID válido? (geralmente 0 ou 1)
- [ ] Qual é o maior ID observado? (o que a app me mostrou)
- [ ] Há gaps? (IDs deletados retornam 404 ou erro?)
- [ ] Response para ID inválido vs inexistente vs não autorizado difere?
  - `200` com dados = acessível
  - `403` = existe mas bloqueado (confirma IDOR parcial — sabe que existe)
  - `404` = não existe
  - `302` redirect = pode indicar auth check
  - `500` = erro inesperado (pode vazar info)

---

## Proof Obligations
- Finding é **vulnerable** se trocar o ID retorna dados/ação de outro contexto
- Finding é **guarded** se ownership check server-side bloqueia acesso
- Checks apenas no frontend (esconder botão, JS validation) **NÃO contam**
- Rate limiting **NÃO é fix**; apenas dificulta exploração em massa
- Response code diferente (403 vs 200) para IDs de outros users já é information disclosure

## False Positives a Evitar
- Endpoint retorna dados públicos por design (e.g., perfil público)
- ID no URL mas objeto é filtrado server-side por sessão
- Objeto pertence ao mesmo user (e.g., múltiplas sessões)
- API retorna 200 mas com corpo vazio/genérico para IDs de outros

---

## Formato do Deliverable → `deliverables/03f_vuln_idor.md`

### Seções:
1. **Executive Summary** — Quantos endpoints testados, quantos vulneráveis
2. **Superfície IDOR Identificada** — Tabela de todos os endpoints com IDs
3. **Análise de Previsibilidade** — Tipo de ID, range, padrão
4. **Findings** — Cada IDOR encontrado com evidência
5. **Controles Observados** — O que a app faz certo
6. **Blind Spots** — O que não foi possível testar (e.g., endpoints que requerem role específico)

---

## Fila de Exploração
```json
{
  "ID": "IDOR-VULN-XX",
  "vulnerability_type": "Horizontal|Vertical|Static_File",
  "endpoint": "METHOD /path/:id",
  "parameter": "id|filename|customer_number",
  "id_type": "sequential|uuid_v1|predictable_hash|timestamp",
  "observed_range": "0-500",
  "auth_required": true,
  "ownership_check": "missing|frontend_only|bypassable",
  "object_type": "PII|credentials|PCAP|financial|config|logs",
  "impact": "data_leak|priv_esc|credential_theft",
  "confidence": "High|Medium|Low",
  "minimal_witness": "curl -b 'session=USERB' http://TARGET/download/0  # retorna PCAP de USERA"
}
```
````
