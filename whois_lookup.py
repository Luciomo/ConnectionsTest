#!/usr/bin/env python3
import whois
import sys
from urllib.parse import urlparse
import json
import datetime
import socket
import re

def extrair_dominio(url):
    """
    Extrai o domínio principal de uma URL.
    Ex: https://www.google.com/search -> www.google.com
    """
    if not url:
        return None
    
    # Adiciona http se não houver esquema, para o urlparse funcionar corretamente
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return url

def simple_socket_whois(domain):
    """
    Fallback: Realiza consulta WHOIS via socket cru quando a biblioteca falha.
    Útil no Windows quando o executável 'whois' não está instalado.
    """
    server = "whois.iana.org"
    
    try:
        # 1. Consulta IANA para achar o servidor correto (Referral)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((server, 43))
        s.send(f"{domain}\r\n".encode())
        
        response_iana = b""
        while True:
            data = s.recv(4096)
            if not data: break
            response_iana += data
        s.close()
        
        response_text = response_iana.decode(errors='ignore')
        
        # Procura por referral (indicação de outro servidor)
        match = re.search(r"refer:\s*([a-zA-Z0-9\.-]+)", response_text, re.IGNORECASE)
        if match:
            server = match.group(1)
            # 2. Consulta o servidor definitivo
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((server, 43))
            s.send(f"{domain}\r\n".encode())
            
            response_final = b""
            while True:
                data = s.recv(4096)
                if not data: break
                response_final += data
            s.close()
            response_text = response_final.decode(errors='ignore')

        # Extração básica de dados via Regex para manter compatibilidade
        dados = {'domain_name': domain, 'raw_text': response_text} # Guarda o texto completo
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'(?:Creation Date|Created On):\s*(.+)',
            'expiration_date': r'(?:Registry Expiry Date|Expiration Date|Expires On):\s*(.+)',
            'org': r'(?:Registrant Organization|Tech Organization):\s*(.+)',
            'country': r'(?:Registrant Country|Tech Country):\s*(.+)',
            'emails': r'[\w\.-]+@[\w\.-]+\.\w+'
        }
        
        for key, pattern in patterns.items():
            if key == 'emails':
                emails = re.findall(pattern, response_text)
                if emails: dados[key] = list(set(emails))
            else:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match: dados[key] = match.group(1).strip()
        
        return dados

    except Exception as e:
        return {"erro": f"Falha no fallback socket: {str(e)}"}

def consultar_whois(url):
    """Realiza a consulta WHOIS para o domínio da URL fornecida."""
    dominio = extrair_dominio(url)
    print(f"🔍 Consultando WHOIS para: {dominio}...")
    
    try:
        # Verifica qual biblioteca está instalada e chama o método apropriado
        # 'python-whois' usa .whois(), enquanto o pacote 'whois' usa .query()
        if hasattr(whois, 'whois'):
            w = whois.whois(dominio)
        elif hasattr(whois, 'query'):
            w = whois.query(dominio)
        else:
            return {"erro": "Método de consulta não encontrado. Verifique se instalou 'python-whois'."}
        return w
    except Exception as e:
        # Se for erro de arquivo não encontrado (WinError 2), usa o fallback
        erro_str = str(e)
        if "[WinError 2]" in erro_str or isinstance(e, FileNotFoundError):
            print(f"⚠️  Executável whois não encontrado. Usando método socket direto...")
            return simple_socket_whois(dominio)
        return {"erro": f"Falha na consulta WHOIS: {erro_str}"}

def formatar_valor(valor):
    """Ajuda a formatar datas e listas para exibição."""
    if isinstance(valor, list):
        return ", ".join([str(v) for v in valor])
    if isinstance(valor, datetime.datetime):
        return valor.strftime("%Y-%m-%d %H:%M:%S")
    return str(valor)

def main():
    if len(sys.argv) < 2:
        url_input = input("Digite a URL ou domínio para consulta WHOIS: ")
    else:
        url_input = sys.argv[1]

    resultado = consultar_whois(url_input)

    print("\n" + "="*40)
    print("RESULTADO WHOIS")
    print("="*40)

    if "erro" in resultado:
        print(f"❌ {resultado['erro']}")
    else:
        for chave, valor in resultado.items():
            # Mostra todos os campos preenchidos
            if valor:
                print(f"{chave.replace('_', ' ').title().ljust(20)}: {formatar_valor(valor)}")
    
    print("="*40 + "\n")

if __name__ == "__main__":
    main()