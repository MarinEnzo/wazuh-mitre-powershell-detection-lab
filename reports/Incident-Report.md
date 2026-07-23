# Incident Report

## Incident Information

| Campo | Valor |
|-------|--------|
| Incident ID | IR-2026-001 |
| Data | 23/07/2026 |
| Analista | Marin |
| Severidade | Média |
| Status | Encerrado |
| Ferramenta | Wazuh 4.12 |
| Fonte | Sysmon Event ID 1 |

---

# Executive Summary

Durante atividades de validação do laboratório de Detection Engineering foi identificado um evento relacionado à execução do PowerShell.

O evento foi coletado pelo Sysmon (Event ID 1), enviado ao Wazuh Agent, processado pelo Wazuh Manager e correlacionado pela regra personalizada 100100.

Após análise foi confirmado tratar-se de uma execução autorizada utilizada exclusivamente para validação da regra personalizada baseada na técnica MITRE ATT&CK T1059.001.

Não foram identificados indícios de comprometimento.

---

# Timeline

| Horário | Evento |
|----------|--------|
| 17:29 | Execução do PowerShell |
| 17:29 | Sysmon registra Event ID 1 |
| 17:29 | Evento enviado ao Wazuh |
| 17:29 | Regra 92027 acionada |
| 17:29 | Regra personalizada 100100 acionada |
| 17:30 | Investigação iniciada |
| 17:35 | Evento validado como teste controlado |

---

# Event Details

Rule ID:

100100

Description:

MITRE LAB: PowerShell process execution detected

Severity:

8

MITRE ATT&CK

T1059.001

---

# Root Cause

Execução intencional do PowerShell para validação da lógica de detecção desenvolvida.

---

# Impact Assessment

Nenhum impacto operacional.

Nenhum malware executado.

Nenhuma persistência criada.

Nenhum artefato malicioso encontrado.

---

# Investigation

Durante a análise foram verificadas:

- Processo pai
- Processo filho
- Usuário
- Linha de comando
- Event ID
- Regra acionada
- Técnica MITRE

Todos os indicadores confirmaram tratar-se de atividade legítima.

---

# Containment

Não aplicável.

---

# Eradication

Não aplicável.

---

# Lessons Learned

A integração entre Sysmon e Wazuh permitiu identificar corretamente a execução do PowerShell.

A criação da regra personalizada possibilitou mapear automaticamente o evento para a técnica MITRE ATT&CK T1059.001.

---

# Final Status

Closed

Classification:

False Positive (Laboratory Validation)
