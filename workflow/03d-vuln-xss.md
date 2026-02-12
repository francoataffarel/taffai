# Fase 3d: Análise de Vulnerabilidades — XSS
## Target: {{TARGET}}

> Baseado em: Shannon `vuln-xss.txt`
> Input: `deliverables/02_recon.md` (seção 10: XSS Vectors)
> Output: `deliverables/03d_vuln_xss.md` + fila de exploração

---

## ⚠️ Contexto: Perguntar antes de executar
> Antes de iniciar esta fase, confirmar: **HTB/CTF** ou **Real/Autorizado**?
> Isso determina quais ferramentas e técnicas são aplicáveis.

## Papel
Especialista em XSS. Backward taint analysis: começa no SINK e rastreia até o SOURCE.
Missão: encontrar mismatches de encoding entre o render context e a sanitização aplicada.

## Render Contexts (onde o dado aparece no DOM)
- `HTML_BODY` — precisa de HTML entity encoding
- `HTML_ATTRIBUTE` — precisa de attribute encoding
- `JAVASCRIPT_STRING` — precisa de JS string encoding
- `URL_PARAM` — precisa de URL encoding
- `CSS_VALUE` — precisa de CSS encoding

## Metodologia: Sink-to-Source (Backward Taint)

### Para cada XSS sink do recon:

#### 1. Identificar o Sink
- [ ] innerHTML, document.write, dangerouslySetInnerHTML
- [ ] Template: `{{ variable }}` sem escape, `| safe`, `{!! !!}`
- [ ] jQuery: `.html()`, `.append()`, `.after()`
- [ ] eval(), Function(), setTimeout(string)

#### 2. Traçar Backward
- [ ] Do sink, voltar: quem fornece esse dado?
- [ ] Passar por cada transformação/sanitização
- [ ] Parar quando encontrar: (a) sanitização válida, ou (b) source não confiável

#### 3. Checkpoint: Database Read (Stored XSS)
Se o backward trace chega num DB read SEM sanitizador:
- [ ] Este é um **Critical Checkpoint**
- [ ] Rastrear o WRITE correspondente (qual input grava no DB?)
- [ ] Continuar backward trace a partir do write

#### 4. Avaliar Context Match
- [ ] A sanitização encontrada é adequada para o render context?
- [ ] HTML encoding em contexto `JAVASCRIPT_STRING` = MISMATCH!
- [ ] URL encoding em contexto `HTML_ATTRIBUTE` = MISMATCH!
- [ ] Nenhuma sanitização = VULNERABLE

#### 5. Testar com curl/browser
- [ ] Injetar payload mínimo no source
- [ ] `curl` para verificar reflexão/encoding na resposta
- [ ] Verificar CSP headers

## Tópicos Avançados
- [ ] DOM Clobbering (injetar HTML com id/name que sobrescreve variáveis JS)
- [ ] Mutation XSS (parser do browser "corrige" HTML malformado)
- [ ] Template Injection (Jinja2 `{{7*7}}`, Handlebars)
- [ ] CSP Bypasses (JSONP, script gadgets, base-uri)

## False Positives
- Self-XSS (requer colar payload no próprio browser) — geralmente não é finding
- WAF blocking seu payload ≠ vulnerability não existe (tente bypass)
- Encoding correto para o contexto = SAFE

## Fila de Exploração
```json
{
  "ID": "XSS-VULN-XX",
  "vulnerability_type": "Reflected|Stored|DOM-based",
  "source": "parâmetro/header/storage",
  "source_detail": "file:line do source ou DB read",
  "path": "source → transformações → sink",
  "sink_function": "innerHTML|template.render|etc",
  "render_context": "HTML_BODY|HTML_ATTRIBUTE|JAVASCRIPT_STRING|URL_PARAM|CSS_VALUE",
  "encoding_observed": "sanitização encontrada ou 'None'",
  "mismatch_reason": "porque a sanitização é insuficiente",
  "witness_payload": "payload mínimo",
  "confidence": "high|med|low",
  "notes": "CSP, HttpOnly cookies, WAF behavior"
}
```
