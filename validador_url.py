#!/usr/bin/env python3
import requests
import base64
import os
import sys
import re
import json
from dotenv import load_dotenv

# --- 1. CARREGAMENTO E VALIDAÇÃO DA CONFIGURAÇÃO ---
load_dotenv()
VT_API_KEY = os.getenv('VT_API_KEY')
GSB_API_KEY = os.getenv('GSB_API_KEY')

# --- Funções de Validação e Utilitários ---
def _validate_api_keys_for_cli():
    """Para o modo CLI, avisa sobre chaves ausentes."""
    keys_missing = False
    if not VT_API_KEY or VT_API_KEY == 'coloque_sua_chave_aqui':
        print("⚠️  Aviso: Chave da API do VirusTotal não configurada. A verificação será pulada.", file=sys.stderr)
        keys_missing = True
        
    if not GSB_API_KEY or GSB_API_KEY == 'coloque_sua_chave_do_google_aqui':
        print("⚠️  Aviso: Chave da API do Google Safe Browsing não configurada. A verificação será pulada.", file=sys.stderr)
        keys_missing = True
    
    if keys_missing:
        print("-" * 30, file=sys.stderr)

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

# --- 2. LÓGICA DE VERIFICAÇÃO (RETORNA DICIONÁRIOS) ---

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
            return {
                "serviço": "VirusTotal",
                "malicioso": stats.get('malicious', 0),
                "suspeito": stats.get('suspicious', 0),
                "seguro": stats.get('harmless', 0) + stats.get('undetected', 0),
            }
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
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(endpoint, json=body, timeout=30)

        if response.status_code == 200:
            data = response.json()
            if 'matches' in data:
                return {
                    "serviço": "Google Safe Browsing",
                    "status": "Perigoso",
                    "ameaça": data['matches'][0]['threatType']
                }
            else:
                return {"serviço": "Google Safe Browsing", "status": "Seguro"}
        else:
            return {"serviço": "Google Safe Browsing", "erro": f"Erro na API: {response.status_code}"}
    except Exception as e:
        return {"serviço": "Google Safe Browsing", "erro": f"Erro inesperado: {e}"}

# --- 3. PONTO DE ENTRADA PARA O SCRIPT CLI ---

def _imprimir_relatorio_cli(resultado):
    """Imprime um relatório formatado para a linha de comando."""
    serviço = resultado.get("serviço", "N/A")
    print(f"\n--- Relatório {serviço} ---")

    if "erro" in resultado:
        print(f"❌ {resultado['erro']}")
        return

    if serviço == "VirusTotal":
        print(f"🔴 Malicioso: {resultado.get('malicioso', 'N/A')}")
        print(f"🟡 Suspeito: {resultado.get('suspeito', 'N/A')}")
        print(f"🟢 Seguro: {resultado.get('seguro', 'N/A')}")
        if resultado.get('malicioso', 0) > 0 or resultado.get('suspeito', 0) > 0:
            print("➡️  Resultado: PERIGOSO")
        else:
            print("➡️  Resultado: SEGURO")
    
    elif serviço == "Google Safe Browsing":
        status = resultado.get("status", "N/A")
        if status == "Perigoso":
            print(f"🔴 Ameaça encontrada: {resultado.get('ameaça', 'N/A')}")
            print("➡️  Resultado: PERIGOSO")
        else:
            print("🟢 Nenhuma ameaça encontrada.")
            print("➡️  Resultado: SEGURO")
    else:
        print(f"⚪ {resultado.get('status', 'Status desconhecido')}")


def main_cli():
    """Função principal para execução via linha de comando."""
    _validate_api_keys_for_cli()
    
    link_usuario = input("Cole o link suspeito aqui: ")
    
    if not is_valid_url(link_usuario):
        print("❌ URL inválida. Por favor, insira uma URL válida começando com http:// ou https://")
        return

    print(f"\n🔗 Analisando: {link_usuario}\n" + "="*30)
    
    resultado_vt = verificar_com_virustotal(link_usuario)
    _imprimir_relatorio_cli(resultado_vt)

    resultado_gsb = verificar_com_google(link_usuario)
    _imprimir_relatorio_cli(resultado_gsb)
    
    print("\n" + "="*30 + "\nAnálise concluída.")

if __name__ == "__main__":
    main_cli()