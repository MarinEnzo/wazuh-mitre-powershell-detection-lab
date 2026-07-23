# Guia de Instalação e Configuração

## 1. Visão geral

Este documento descreve a instalação e configuração do laboratório utilizado no projeto **Wazuh MITRE ATT&CK PowerShell Detection Lab**.

O ambiente foi criado para coletar eventos de criação de processos no Windows por meio do Microsoft Sysmon, encaminhá-los ao Wazuh e gerar um alerta personalizado associado à técnica MITRE ATT&CK `T1059.001 — PowerShell`.

> Este projeto foi desenvolvido exclusivamente em ambiente controlado. Nenhum malware real foi utilizado.

---

## 2. Arquitetura do laboratório

O laboratório foi composto por duas máquinas virtuais.

| Máquina | Sistema operacional | Endereço IP | Função |
|---|---|---:|---|
| Wazuh Server | Ubuntu Server | `192.168.10.20` | Wazuh Manager e Wazuh Dashboard |
| Windows Endpoint | Windows 10 | `192.168.10.30` | Wazuh Agent, Sysmon e geração de telemetria |

### Fluxo de comunicação

```mermaid
flowchart LR
    A[Windows 10] -->|Eventos Sysmon| B[Wazuh Agent]
    B -->|Comunicação do agente| C[Wazuh Manager]
    C --> D[Wazuh Dashboard]
```

---

## 3. Tecnologias utilizadas

- Oracle VirtualBox
- Ubuntu Server
- Windows 10
- Wazuh Manager
- Wazuh Dashboard
- Wazuh Agent
- Microsoft Sysmon
- Windows Event Viewer
- MITRE ATT&CK
- Regras XML do Wazuh

---

## 4. Requisitos do laboratório

Antes de iniciar, foram considerados os seguintes requisitos:

- conectividade entre as duas máquinas virtuais;
- endereço IP válido para o Wazuh Server;
- privilégios administrativos no Windows;
- acesso com `sudo` no Ubuntu;
- Wazuh Manager e Dashboard instalados;
- agente Wazuh instalado no endpoint Windows;
- Sysmon instalado no endpoint Windows.

---

## 5. Validação da conectividade

No Windows, a conectividade com o servidor Wazuh pode ser validada com:

```powershell
ping 192.168.10.20
```

No Ubuntu, a conectividade com o endpoint Windows pode ser testada com:

```bash
ping 192.168.10.30
```

A ausência de resposta ao `ping` não significa necessariamente falha de comunicação, pois o firewall pode bloquear ICMP. Nesse caso, também devem ser avaliadas as portas utilizadas pelo agente Wazuh.

---

## 6. Instalação do Wazuh Agent no Windows

O Wazuh Agent foi instalado no endpoint Windows e configurado para se comunicar com o endereço do Wazuh Manager:

```text
192.168.10.20
```

Após a instalação, o serviço foi validado no PowerShell:

```powershell
Get-Service WazuhSvc
```

Resultado esperado:

```text
Status   Name       DisplayName
------   ----       -----------
Running  WazuhSvc   Wazuh
```

Também é possível validar o serviço utilizando:

```powershell
sc.exe query WazuhSvc
```

---

## 7. Validação do agente no Wazuh Dashboard

Após a instalação e comunicação inicial, o agente deve aparecer no Dashboard como:

```text
Active
```

Os principais dados a serem validados são:

- nome do agente;
- endereço IP;
- sistema operacional;
- última conexão;
- status do agente.

<!-- Inserir imagem: agente conectado ao Wazuh -->

---

## 8. Instalação do Microsoft Sysmon

O Sysmon foi instalado no Windows com privilégios administrativos.

Exemplo de instalação:

```powershell
Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Caso não seja utilizada uma configuração personalizada:

```powershell
Sysmon64.exe -accepteula -i
```

Após a instalação, o serviço pode ser validado com:

```powershell
Get-Service Sysmon64
```

Resultado esperado:

```text
Status   Name      DisplayName
------   ----      -----------
Running  Sysmon64  Sysmon64
```

<!-- Inserir imagem: instalação do Sysmon -->

<!-- Inserir imagem: serviço Sysmon64 em execução -->

---

## 9. Validação dos eventos do Sysmon

Os eventos do Sysmon podem ser visualizados no Windows Event Viewer.

Caminho:

```text
Applications and Services Logs
└── Microsoft
    └── Windows
        └── Sysmon
            └── Operational
```

Para este projeto, o principal evento utilizado foi:

| Event ID | Descrição |
|---:|---|
| 1 | Process Creation |

O Event ID 1 contém informações relevantes para investigação, incluindo:

- imagem do processo;
- linha de comando;
- processo pai;
- usuário;
- horário de execução;
- identificadores do processo;
- hashes, quando habilitados na configuração.

<!-- Inserir imagem: Sysmon Event ID 1 no Event Viewer -->

---

## 10. Configuração da coleta do Sysmon no Wazuh Agent

O arquivo de configuração do agente está localizado em:

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

O arquivo deve ser aberto com um editor de texto executado como administrador.

Exemplo:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

A coleta do canal Sysmon pode ser configurada com:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Após salvar o arquivo, o serviço do agente deve ser reiniciado:

```powershell
Restart-Service WazuhSvc
```

Também pode ser utilizado:

```powershell
net stop WazuhSvc
net start WazuhSvc
```

---

## 11. Validação dos eventos no Wazuh

Após a configuração, os eventos Sysmon devem aparecer no Wazuh Dashboard.

A validação pode ser realizada em:

```text
Threat Hunting
```

Filtros úteis:

```text
rule.groups: sysmon
```

```text
data.win.system.eventID: 1
```

```text
data.win.eventdata.image: *powershell.exe
```

Os nomes dos campos podem variar de acordo com a versão, decoder e estrutura do evento.

<!-- Inserir imagem: eventos Sysmon no Wazuh -->

---

## 12. Backup das regras locais

Antes de alterar o arquivo de regras, foi criado um backup:

```bash
sudo cp /var/ossec/etc/rules/local_rules.xml \
/var/ossec/etc/rules/local_rules.xml.backup
```

Esse procedimento permite restaurar a configuração anterior em caso de erro de sintaxe ou comportamento inesperado.

---

## 13. Criação da regra personalizada

O arquivo utilizado para a regra foi:

```text
/var/ossec/etc/rules/local_rules.xml
```

Ele pode ser editado com:

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Regra criada:

```xml
<group name="windows,powershell,mitre_lab,">

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

</group>
```

<!-- Inserir imagem: regra personalizada no local_rules.xml -->

---

## 14. Reinicialização do Wazuh Manager

Após salvar a regra, o Wazuh Manager foi reiniciado:

```bash
sudo systemctl restart wazuh-manager
```

O status foi validado com:

```bash
sudo systemctl status wazuh-manager
```

Resultado esperado:

```text
Active: active (running)
```

O reinício bem-sucedido indica que o serviço conseguiu carregar as configurações. Entretanto, a validação funcional ainda deve ser realizada por meio da geração de um evento real.

<!-- Inserir imagem: Wazuh Manager ativo -->

---

## 15. Geração do evento de teste

No endpoint Windows, foi aberta uma sessão do PowerShell para gerar um evento de criação de processo.

Exemplo benigno:

```powershell
powershell.exe -NoProfile -Command "Write-Output 'MITRE T1059.001 Detection Test'"
```

Esse comando apenas exibe uma mensagem e não executa nenhuma ação maliciosa.

O fluxo esperado é:

```text
Execução do PowerShell
        ↓
Sysmon Event ID 1
        ↓
Wazuh Agent
        ↓
Wazuh Manager
        ↓
Regra nativa 92027
        ↓
Regra personalizada 100100
```

---

## 16. Validação da regra personalizada

No Wazuh Dashboard, a regra pode ser localizada utilizando:

```text
rule.id: 100100
```

Também pode ser utilizado:

```text
rule.mitre.id: T1059.001
```

Dados esperados:

| Campo | Valor |
|---|---|
| Rule ID | `100100` |
| Level | `8` |
| Description | `MITRE LAB: PowerShell process execution detected` |
| MITRE ATT&CK | `T1059.001` |
| Fonte | Sysmon Event ID 1 |

<!-- Inserir imagem: alerta da regra 100100 -->

<!-- Inserir imagem: detalhes da regra -->

---

## 17. Resultado

A integração foi validada com sucesso.

O Sysmon registrou a criação do processo PowerShell, o Wazuh Agent coletou o evento e o Wazuh Manager acionou a regra personalizada `100100`.

O alerta foi associado à técnica MITRE ATT&CK `T1059.001`.

---

## 18. Considerações de segurança

Antes de publicar evidências no GitHub, devem ser removidos ou ocultados:

- senhas;
- tokens;
- chaves de API;
- endereços IP públicos;
- dados de clientes;
- nomes de usuários sensíveis;
- nomes reais de máquinas corporativas;
- credenciais ou informações pessoais.

Os endereços IP privados usados neste laboratório pertencem exclusivamente ao ambiente virtual de testes.
