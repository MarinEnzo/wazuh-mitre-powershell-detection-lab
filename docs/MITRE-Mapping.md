# Mapeamento MITRE ATT&CK

## 1. Visão geral

Este documento descreve o mapeamento da regra personalizada `100100` para a técnica MITRE ATT&CK relacionada à execução do PowerShell.

| Campo | Valor |
|---|---|
| Framework | MITRE ATT&CK |
| Tática | Execution |
| Técnica | Command and Scripting Interpreter |
| Técnica ID | `T1059` |
| Subtécnica | PowerShell |
| Subtécnica ID | `T1059.001` |
| Regra Wazuh | `100100` |
| Fonte de dados | Microsoft Sysmon |
| Evento | Event ID 1 — Process Creation |

---

## 2. MITRE ATT&CK

O MITRE ATT&CK é uma base de conhecimento utilizada para organizar táticas, técnicas e subtécnicas observadas em atividades adversárias.

No contexto de Detection Engineering, o framework ajuda a:

- classificar comportamentos detectados;
- avaliar cobertura de monitoramento;
- organizar regras de detecção;
- apoiar investigações;
- estruturar atividades de threat hunting;
- comunicar riscos de forma padronizada.

---

## 3. Tática: Execution

A tática `Execution` representa comportamentos relacionados à execução de código, comandos ou scripts em um sistema.

Neste projeto, a execução observada foi a inicialização do PowerShell no endpoint Windows.

```text
Tática: Execution
```

---

## 4. Técnica: Command and Scripting Interpreter

A técnica `T1059` representa o uso de interpretadores de comandos e scripts.

Esses interpretadores podem ser usados para:

- executar comandos;
- automatizar tarefas;
- administrar sistemas;
- iniciar scripts;
- interagir com recursos do sistema operacional.

Por serem ferramentas legítimas, seu uso precisa ser analisado dentro do contexto operacional.

```text
Técnica: T1059 — Command and Scripting Interpreter
```

---

## 5. Subtécnica: PowerShell

O PowerShell é um interpretador de comandos e uma plataforma de automação presente em ambientes Windows.

Ele pode ser utilizado legitimamente por:

- administradores;
- equipes de suporte;
- desenvolvedores;
- sistemas de gerenciamento;
- ferramentas de automação.

Também pode ser utilizado em atividades adversárias, especialmente para execução de comandos e scripts.

```text
Subtécnica: T1059.001 — PowerShell
```

---

## 6. Justificativa do mapeamento

A regra `100100` é acionada após a identificação de um evento relacionado à execução do PowerShell.

O comportamento observado corresponde à inicialização do processo:

```text
powershell.exe
```

Como o evento representa o uso do interpretador PowerShell, ele foi associado à subtécnica:

```text
T1059.001
```

A associação não significa que o evento seja automaticamente malicioso. Ela informa qual comportamento técnico está sendo observado.

---

## 7. Fonte de telemetria

A telemetria foi fornecida pelo Microsoft Sysmon.

Evento utilizado:

```text
Event ID 1 — Process Creation
```

O Event ID 1 registra informações sobre a criação de processos e pode fornecer dados como:

- executável;
- linha de comando;
- processo pai;
- usuário;
- horário;
- identificadores de processo;
- hashes;
- nível de integridade.

---

## 8. Relação entre evento e técnica

```mermaid
flowchart LR
    A[PowerShell executado] --> B[Sysmon Event ID 1]
    B --> C[Wazuh Agent]
    C --> D[Wazuh Manager]
    D --> E[Rule 92027]
    E --> F[Rule 100100]
    F --> G[T1059.001 PowerShell]
```

---

## 9. Implementação no Wazuh

A associação com o MITRE ATT&CK foi realizada no bloco:

```xml
<mitre>
  <id>T1059.001</id>
</mitre>
```

Regra completa:

```xml
<rule id="100100" level="8">
  <if_sid>92027</if_sid>

  <description>
    MITRE LAB: PowerShell process execution detected
  </description>

  <mitre>
    <id>T1059.001</id>
  </mitre>

  <group>
    execution,powershell_detection,mitre_t1059_001,
  </group>
</rule>
```

---

## 10. Benefícios do mapeamento

O mapeamento permite:

### Organização de alertas

Os eventos podem ser agrupados pela técnica MITRE correspondente.

### Threat hunting

O analista pode pesquisar eventos relacionados a uma técnica específica.

Exemplo:

```text
rule.mitre.id: T1059.001
```

### Avaliação de cobertura

A equipe pode identificar quais técnicas possuem detecções implementadas.

### Comunicação técnica

O uso de um identificador padronizado facilita a comunicação entre analistas, gestores e equipes de resposta a incidentes.

### Criação de dashboards

Os alertas podem ser organizados por tática, técnica, host, usuário e severidade.

---

## 11. Cobertura fornecida pela regra

A regra oferece cobertura para:

```text
Execução de processos PowerShell reconhecidos pela regra nativa 92027.
```

A regra não garante cobertura para:

- PowerShell executado sem telemetria disponível;
- eventos que não sejam coletados pelo agente;
- execução em endpoints sem Sysmon;
- técnicas que evitem a criação de um processo monitorado;
- conteúdo interno de scripts não registrado;
- atividades executadas em hosts desconectados;
- eventos removidos antes da coleta.

---

## 12. Limitações do mapeamento

O MITRE ATT&CK classifica comportamentos, não determina automaticamente intenção.

Uma atividade associada a `T1059.001` pode ser:

- legítima;
- administrativa;
- automatizada;
- suspeita;
- maliciosa.

A classificação final depende da investigação.

---

## 13. Contexto necessário para análise

Para determinar se a execução é suspeita, devem ser analisados:

- usuário;
- endpoint;
- horário;
- linha de comando;
- processo pai;
- processo filho;
- privilégios;
- conexões de rede;
- arquivos criados;
- frequência;
- histórico do ativo;
- outros alertas relacionados.

---

## 14. Possíveis correlações

A detecção pode ser correlacionada com outros comportamentos.

| Comportamento | Possível finalidade investigativa |
|---|---|
| Download de arquivo | Verificar obtenção de payload |
| Criação de tarefa agendada | Investigar persistência |
| Alteração do registro | Investigar persistência ou configuração |
| Conexão de rede incomum | Investigar comunicação externa |
| Processo filho suspeito | Avaliar execução de ferramentas |
| Comando codificado | Avaliar tentativa de ocultação |
| Desativação de segurança | Investigar evasão de defesa |
| Criação de usuário | Investigar persistência ou privilégio |

---

## 15. Consulta de hunting

Consulta principal:

```text
rule.id: 100100
```

Consulta por técnica MITRE:

```text
rule.mitre.id: T1059.001
```

Consulta por descrição:

```text
rule.description: "MITRE LAB: PowerShell process execution detected"
```

Consulta por executável, dependendo do nome do campo disponível:

```text
data.win.eventdata.image: *powershell.exe
```

---

## 16. Matriz de validação

| Teste | Resultado esperado |
|---|---|
| Executar PowerShell | Sysmon gera Event ID 1 |
| Coletar o evento | Wazuh Agent envia o registro |
| Processar o evento | Regra 92027 é acionada |
| Avaliar regra local | Regra 100100 é acionada |
| Verificar MITRE | Alerta contém `T1059.001` |
| Pesquisar no Dashboard | Evento aparece na consulta |

---

## 17. Evidências do projeto

<!-- Inserir imagem: Sysmon Event ID 1 -->

<!-- Inserir imagem: evento recebido no Wazuh -->

<!-- Inserir imagem: regra 100100 no local_rules.xml -->

<!-- Inserir imagem: alerta associado à técnica T1059.001 -->

---

## 18. Melhorias futuras

O projeto pode ser ampliado com:

- PowerShell Script Block Logging;
- Module Logging;
- Transcription;
- análise de linhas de comando codificadas;
- correlação com DNS;
- correlação com conexões de rede;
- análise de processos pai e filho;
- criação de allowlists;
- regras para comportamento administrativo conhecido;
- detecções para outras subtécnicas de `T1059`;
- dashboards de cobertura MITRE ATT&CK.

---

## 19. Conclusão

A regra personalizada `100100` foi mapeada para a subtécnica MITRE ATT&CK `T1059.001 — PowerShell`.

A telemetria utilizada foi o Sysmon Event ID 1, coletado pelo Wazuh Agent e processado pelo Wazuh Manager.

O mapeamento melhora a organização da detecção, auxilia atividades de threat hunting e demonstra como uma regra local pode ser associada a um comportamento descrito pelo MITRE ATT&CK.

A execução detectada no laboratório foi autorizada, controlada e utilizada apenas para validação técnica.
