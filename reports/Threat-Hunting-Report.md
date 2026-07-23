# Threat Hunting Report

## Hunt Name

PowerShell Execution Detection

---

# Objetivo

Identificar execuções de PowerShell potencialmente suspeitas utilizando telemetria do Sysmon integrada ao Wazuh.

---

# Hipótese

Um atacante pode utilizar PowerShell para executar comandos maliciosos sem utilizar arquivos adicionais.

---

# Técnica MITRE

T1059.001

PowerShell

---

# Fonte de Dados

Sysmon

Event ID 1

---

# Ferramentas

- Wazuh
- Sysmon
- Windows Event Viewer

---

# Query

Rule ID

100100

---

# Evidências Encontradas

Evento detectado:

PowerShell Process Execution

Severity

8

MITRE

T1059.001

---

# Investigação

Foram analisados:

- Processo
- Processo Pai
- Linha de comando
- Usuário
- Horário
- Técnica MITRE

---

# Resultado

A atividade correspondeu à execução controlada realizada durante o laboratório.

Nenhum comportamento malicioso adicional foi identificado.

---

# Conclusão

A regra personalizada demonstrou capacidade para detectar eventos relacionados à execução do PowerShell.

A estratégia de utilizar uma regra derivada da 92027 mostrou-se eficiente e de fácil manutenção.

---

# Recomendações

Expandir a cobertura para:

- T1047 (WMI)

- T1547.001 (Registry Run Keys)

- T1053.005 (Scheduled Tasks)

- T1021 (Remote Services)

- T1112 (Registry)

- T1105 (Ingress Tool Transfer)
