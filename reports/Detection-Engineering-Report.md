# Detection Engineering Report

## Objetivo

Desenvolver uma regra personalizada para identificar execuções do PowerShell utilizando telemetria do Sysmon integrada ao Wazuh.

---

# Contexto

Ataques modernos frequentemente utilizam PowerShell para:

- Download de payloads
- Execução de scripts
- Movimentação lateral
- Coleta de informações
- Execução de comandos

A técnica é catalogada pelo MITRE ATT&CK como:

T1059.001 – PowerShell

---

# Fonte da Telemetria

Microsoft Sysmon

Evento utilizado:

Event ID 1

Descrição:

Process Creation

---

# Pipeline da Detecção

PowerShell

↓

Sysmon Event ID 1

↓

Windows Event Log

↓

Wazuh Agent

↓

Wazuh Manager

↓

Rule 92027

↓

Rule 100100

↓

MITRE T1059.001

---

# Regra Desenvolvida

ID:

100100

Level:

8

Tipo:

Local Rule

Herança:

if_sid 92027

---

# Lógica Utilizada

Ao invés de criar uma regra completamente independente, foi utilizada a regra nativa 92027 como ponto de partida.

Dessa forma:

- aproveita-se o decoder existente;
- reduz-se manutenção;
- melhora-se compatibilidade com futuras atualizações.

---

# MITRE Mapping

Technique

T1059.001

Execution

PowerShell

---

# Benefícios

- Redução de falsos positivos
- Correlação automática
- Melhor classificação de eventos
- Facilidade para Threat Hunting

---

# Resultado

A regra identificou corretamente a execução do PowerShell.

Todos os testes realizados produziram alertas esperados.

---

# Melhorias Futuras

Adicionar detecções para:

- CMD
- WMI
- Registry Run Keys
- Scheduled Tasks
- PsExec
- Remote Services
