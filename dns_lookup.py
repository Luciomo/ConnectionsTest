#!/usr/bin/env python3
import dns.resolver
from urllib.parse import urlparse

def extrair_dominio(url):
    """
    Extrai o domínio principal de uma URL, removendo protocolo e porta.
    """
    if not url:
        return None
    
    # Adiciona http se não houver esquema, para o urlparse funcionar
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urlparse(url)
        # Remove a porta se existir (ex: site.com:8080 -> site.com)
        dominio = parsed.netloc.split(':')[0]
        return dominio
    except Exception:
        return url

def consultar_dns(url):
    """
    Consulta registros DNS (A, MX, NS, TXT) para o domínio fornecido.
    """
    dominio = extrair_dominio(url)
    resultados = {}
    
    # Tipos de registros que queremos buscar
    tipos_registro = ['A', 'MX', 'NS', 'TXT']
    
    print(f"🌐 Consultando DNS para: {dominio}...")

    try:
        for tipo in tipos_registro:
            try:
                respostas = dns.resolver.resolve(dominio, tipo)
                lista_respostas = []
                for rdata in respostas:
                    lista_respostas.append(rdata.to_text())
                if lista_respostas:
                    resultados[tipo] = lista_respostas
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue # Apenas ignora se não houver registro desse tipo
            except Exception as e:
                resultados[tipo] = [f"Erro ao buscar: {str(e)}"]
                
        return resultados
    except dns.resolver.NXDOMAIN:
        return {"erro": "Domínio não encontrado (NXDOMAIN)."}
    except Exception as e:
        return {"erro": f"Falha geral no DNS: {str(e)}"}