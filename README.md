# Teste Links e conexões 🛡️

**Connections Test ** é uma ferramenta de segurança e diagnóstico de rede desenvolvida em Python com Flask. O objetivo do projeto é permitir a análise rápida de URLs suspeitas, verificando sua reputação em bases de dados de segurança, além de fornecer utilitários de rede como Ping, Traceroute e Teste de Velocidade.

## 🚀 Funcionalidades

*   **Análise de Reputação de URLs:**
    *   Integração com **VirusTotal API** para detectar malwares e sites phishing.
    *   Integração com **Google Safe Browsing API** para verificar ameaças conhecidas.
*   **Ferramentas de Diagnóstico:**
    *   **WHOIS:** Consulta informações de registro de domínios.
    *   **DNS Lookup:** Verifica registros A, MX, NS e TXT.
    *   **Ping:** Teste de latência com suporte a IPv4 e IPv6.
    *   **Tracert (Traceroute):** Rastreamento de rota de pacotes.
    *   **Teste de Conexão:** Medição de Latência, Jitter e Velocidade (Download/Upload).
*   **Interface Web:**
    *   Design responsivo e moderno.
    *   **Modo Escuro (Dark Mode)** automático ou manual.
    *   Exportação de relatórios em **PDF**.
    *   Histórico visual de resultados.

## 📋 Pré-requisitos

*   Python 3.8 ou superior.
*   Conexão com a internet.
*   Chaves de API (Opcional, mas recomendado para análise de reputação):
    *   [VirusTotal API Key](https://www.virustotal.com/)
    *   [Google Safe Browsing API Key](https://developers.google.com/safe-browsing/v4)

## 🔧 Instalação

1.  **Clone o repositório ou baixe os arquivos:**

    ```bash
    git clone https://github.com/seu-usuario/VerificaZap.git
    cd VerificaZap
    ```

2.  **Crie um ambiente virtual (Recomendado):**

    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate

    # Linux/Mac
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Instale as dependências:**

    ```bash
    pip install -r requirements.txt
    ```

## ⚙️ Configuração

Para que as verificações de segurança funcionem corretamente, você precisa configurar as variáveis de ambiente.

1.  Crie um arquivo chamado `.env` na raiz do projeto.
2.  Adicione suas chaves de API no seguinte formato:

    ```env
    VT_API_KEY=sua_chave_do_virustotal_aqui
    GSB_API_KEY=sua_chave_do_google_safe_browsing_aqui
    ```

> **Nota:** Se não configurar as chaves, as funcionalidades de VirusTotal e Google Safe Browsing retornarão erros ou avisos, mas as ferramentas de rede (Ping, DNS, etc.) continuarão funcionando.

## ▶️ Como Executar

1.  Certifique-se de que o ambiente virtual está ativado.
2.  Execute o aplicativo Flask:

    ```bash
    python app.py
    ```

3.  Abra o seu navegador e acesse:
    `http://127.0.0.1:5500` (ou a porta indicada no terminal).

## 📂 Estrutura do Projeto

*   `app.py`: Arquivo principal da aplicação Flask e rotas.
*   `templates/`: Arquivos HTML (Jinja2) para a interface.
*   `static/`: Arquivos CSS e assets (ícones).
*   `connection_test.py`, `dns_lookup.py`, `ping.py`, `tracert.py`, `whois_lookup.py`: Módulos auxiliares para cada funcionalidade.
*   `validador_url.py`: Script para validação via linha de comando (CLI).

## 👤 Autor

Desenvolvido por **Lúcio Macedo**.
Projeto de estudo para DevOps e Lógica de Programação.

---
&copy; 2026 Connections Test
