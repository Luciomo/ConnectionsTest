#!/usr/bin/env python3
import requests
import base64
import os
import sys
import re
import json
import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for

import whois_lookup
import dns_lookup
import ping
import tracert
import connection_test

# --- 1. CONFIGURAÇÃO E INICIALIZAÇÃO ---
load_dotenv()
app = Flask(__name__)

@app.context_processor
def inject_year():
    """Injeta o ano atual em todos os templates."""
    return {'current_year': datetime.datetime.now().year}

# --- 2. LÓGICA DE VERIFICAÇÃO DE URLS ---
# (Anteriormente em validador_url.py)

VT_API_KEY = os.getenv('VT_API_KEY')
GSB_API_KEY = os.getenv('GSB_API_KEY')

def is_valid_url(url):
    """Valida se a string fornecida é uma URL bem formada."""
    if not isinstance(url, str): return False
    regex = re.compile(
        (
            r'^(?:http|ftp)s?://'
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
            r'localhost|'
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            r'(?::\d+)?'
            r'(?:/?|[/?]\S+)$'
        ), re.IGNORECASE)
    return re.match(regex, url) is not None

def normalizar_url(url):
    """Adiciona o esquema http:// se a URL não possuir, para permitir validação."""
    if url and not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

def verificar_com_virustotal(url):
    """Verifica uma URL com VirusTotal e retorna um dicionário com os resultados."""
    if not VT_API_KEY or VT_API_KEY == 'coloque_sua_chave_aqui':
        return {"serviço": "VirusTotal", "erro": "Chave de API não configurada."}

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY, "accept": "application/json"}
        response = requests.get(endpoint, headers=headers, timeout=30)

        if response.status_code == 200:
            stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {"serviço": "VirusTotal", "malicioso": stats.get('malicious', 0), "suspeito": stats.get('suspicious', 0), "seguro": stats.get('harmless', 0) + stats.get('undetected', 0)}
        elif response.status_code == 404:
            return {"serviço": "VirusTotal", "status": "Não encontrado no banco de dados."}
        else:
            return {"serviço": "VirusTotal", "erro": f"Erro na API: {response.status_code}"}
    except Exception as e:
        return {"serviço": "VirusTotal", "erro": f"Erro inesperado: {e}"}

def verificar_com_google(url):
    """Verifica uma URL com Google Safe Browsing e retorna um dicionário."""
    if not GSB_API_KEY or GSB_API_KEY == 'coloque_sua_chave_do_google_aqui':
        return {"serviço": "Google Safe Browsing", "erro": "Chave de API não configurada."}

    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
        body = {
            "client": {"clientId": "VerificaZap", "clientVersion": "1.1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=body, timeout=30)

        if response.status_code == 200:
            data = response.json()
            if 'matches' in data:
                return {"serviço": "Google Safe Browsing", "status": "Perigoso", "ameaça": data['matches'][0]['threatType']}
            else:
                return {"serviço": "Google Safe Browsing", "status": "Seguro"}
        else:
            return {"serviço": "Google Safe Browsing", "erro": f"Erro na API: {response.status_code}"}
    except Exception as e:
        return {"serviço": "Google Safe Browsing", "erro": f"Erro inesperado: {e}"}

# --- 3. ROTAS DA APLICAÇÃO WEB ---

@app.route('/')
def index():
    """Renderiza a página inicial com o formulário."""
    return render_template('index.html', active_page='home')

@app.route('/check', methods=['POST'])
def check():
    """Recebe a URL do formulário, analisa e exibe os resultados."""
    url = request.form.get('url')
    
    url_normalized = normalizar_url(url)

    if not is_valid_url(url_normalized):
        return "URL inválida. Por favor, volte e insira uma URL válida.", 400

    vt_result = verificar_com_virustotal(url_normalized)
    gsb_result = verificar_com_google(url_normalized)
    whois_result = whois_lookup.consultar_whois(url_normalized)
    dns_result = dns_lookup.consultar_dns(url_normalized)
    
    return render_template('results.html', url=url_normalized, vt_result=vt_result, gsb_result=gsb_result, whois_result=whois_result, dns_result=dns_result, formatar_valor=whois_lookup.formatar_valor, active_page='home')

@app.route('/dns')
def dns_page():
    """Renderiza a página específica de consulta DNS."""
    return render_template('dns-lookup.html', active_page='dns')

@app.route('/check_dns', methods=['POST'])
def check_dns():
    """Realiza apenas a consulta DNS."""
    url = request.form.get('url')
    
    url_normalized = normalizar_url(url)

    # Realiza apenas a consulta DNS
    dns_result = dns_lookup.consultar_dns(url_normalized)
    
    # Passa None para os outros resultados para que o template saiba que não deve exibi-los
    return render_template('results.html', url=url_normalized, vt_result=None, gsb_result=None, whois_result=None, dns_result=dns_result, formatar_valor=whois_lookup.formatar_valor, active_page='dns')

@app.route('/whois')
def whois_page():
    """Renderiza a página específica de consulta WHOIS."""
    return render_template('whois.html', active_page='whois')

@app.route('/check_whois', methods=['POST'])
def check_whois():
    """Realiza apenas a consulta WHOIS."""
    url = request.form.get('url')
    
    url_normalized = normalizar_url(url)

    # Realiza apenas a consulta WHOIS
    whois_result = whois_lookup.consultar_whois(url_normalized)
    
    # Passa None para os outros resultados
    return render_template('results.html', url=url_normalized, vt_result=None, gsb_result=None, whois_result=whois_result, dns_result=None, formatar_valor=whois_lookup.formatar_valor, active_page='whois')

@app.route('/ping')
def ping_page():
    """Renderiza a página específica de Ping."""
    return render_template('ping.html', active_page='ping')

@app.route('/check_ping', methods=['POST'])
def check_ping():
    """Realiza apenas o Ping."""
    url = request.form.get('url')
    url_normalized = normalizar_url(url)
    
    ping_result = ping.executar_ping(url_normalized)
    
    return render_template('results.html', 
                           url=url_normalized, 
                           ping_result=ping_result, 
                           active_page='ping',
                           formatar_valor=whois_lookup.formatar_valor)

@app.route('/tracert')
def tracert_page():
    """Renderiza a página específica de Tracert."""
    return render_template('tracert.html', active_page='tracert')

@app.route('/check_tracert', methods=['POST'])
def check_tracert():
    """Realiza apenas o Tracert."""
    url = request.form.get('url')
    url_normalized = normalizar_url(url)
    
    # Aviso: Tracert pode demorar um pouco
    tracert_result = tracert.executar_tracert(url_normalized)
    
    return render_template('results.html', 
                           url=url_normalized, 
                           tracert_result=tracert_result, 
                           active_page='tracert',
                           formatar_valor=whois_lookup.formatar_valor)

@app.route('/connection')
def connection_page():
    """Renderiza a página de Teste de Conexão."""
    return render_template('connection.html', active_page='connection')

@app.route('/check_connection', methods=['POST'])
def check_connection():
    """Realiza o teste de conexão (Latência, Jitter, Speedtest)."""
    url = request.form.get('url')
    # Extrai apenas o host/IP para o ping3 funcionar corretamente
    host = ping.extrair_host(url)
    
    # Aviso: Speedtest demora
    conn_result = connection_test.executar_teste_conexao(host)
    
    return render_template('results.html', 
                           url=host, 
                           conn_result=conn_result, 
                           active_page='connection',
                           formatar_valor=whois_lookup.formatar_valor)

@app.route('/api/ping_pong')
def api_ping_pong():
    """Endpoint leve para medir latência do cliente (browser) até este servidor."""
    return {"message": "pong", "ip": request.remote_addr}, 200

# --- 4. PONTO DE ENTRADA PRINCIPAL ---

if __name__ == '__main__':
    # --- INSTRUÇÕES PARA EXECUTAR ---
    # 1. Certifique-se de que seu ambiente virtual está ativado.
    # 2. Execute este script diretamente: python app.py
    # 3. Abra seu navegador e acesse: http://127.0.0.1:5500
    #
    # O modo debug NUNCA deve ser usado em um ambiente de produção!
    app.run(host='0.0.0.0', port=5500, debug=True)
    
    