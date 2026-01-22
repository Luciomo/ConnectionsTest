import requests
import os
import dns.resolver
try:
    from email_validator import validate_email, EmailNotValidError
except ImportError:
    validate_email = None


def verificar_mx(dominio):
    """
    Verifica se o domínio possui registros MX válidos.
    """
    print(f"📨 Verificando registros MX para: {dominio}...")
    try:
        answers = dns.resolver.resolve(dominio, 'MX')
        records = [r.exchange.to_text() for r in answers]
        return {
            "status": "Válido",
            "registros": records
        }
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"status": "Inválido", "erro": "Domínio não possui registros MX ou não existe."}
    except Exception as e:
        return {"status": "Erro", "erro": str(e)}

def verificar_dominio_gsb(dominio):
    """
    Verifica se o domínio do e-mail é considerado perigoso pelo Google Safe Browsing.
    """
    api_key = os.getenv('GSB_API_KEY')
    if not api_key or api_key == 'coloque_sua_chave_do_google_aqui':
        return {"erro": "Chave de API do Google não configurada."}

    url_check = f"http://{dominio}"
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {"clientId": "VerificaZap", "clientVersion": "1.1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url_check}]
        }
    }

    print(f"🔍 Consultando Google Safe Browsing para domínio: {dominio}...")

    try:
        response = requests.post(endpoint, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            if 'matches' in data:
                return {
                    "serviço": "Google Safe Browsing",
                    "status": "Perigoso",
                    "ameaça": data['matches'][0]['threatType']
                }
            else:
                return {
                    "serviço": "Google Safe Browsing",
                    "status": "Seguro"
                }
        else:
            return {"erro": f"Erro na API do Google: {response.status_code}"}
    except Exception as e:
        return {"erro": f"Erro de conexão com Google: {str(e)}"}

def verificar_email(email):
    """
    Verifica se o e-mail está listado na base de dados do StopForumSpam.
    Retorna um dicionário com os resultados.
    """
    if validate_email:
        try:
            # check_deliverability=False valida a sintaxe sem fazer consultas DNS (que faremos depois)
            valid = validate_email(email, check_deliverability=False)
            email = valid.normalized
        except EmailNotValidError as e:
            return {"erro": f"E-mail inválido: {str(e)}"}
    else:
        if not email or '@' not in email:
            return {"erro": "Formato de e-mail inválido."}

    domain = email.split('@')[-1]
    
    # --- 1. Consulta StopForumSpam ---
    # API do StopForumSpam (retorna JSON)
    url = f"http://api.stopforumspam.org/api?email={email}&json"
    
    print(f"📧 Consultando StopForumSpam para: {email}...")

    sfs_result = {}
    try:
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                email_data = data.get('email', {})
                if email_data.get('appears'):
                    sfs_result = {
                        "serviço": "StopForumSpam",
                        "status": "Detectado",
                        "frequencia": email_data.get('frequency', 0),
                        "ultima_vez": email_data.get('lastseen', 'N/A'),
                        "confianca": email_data.get('confidence', 0)
                    }
                else:
                    sfs_result = {
                        "serviço": "StopForumSpam",
                        "status": "Limpo",
                        "mensagem": "Não encontrado na base de spam."
                    }
            else:
                 sfs_result = {"erro": "Erro na resposta da API (formato inesperado)."}
        else:
            sfs_result = {"erro": f"Erro HTTP na API: {response.status_code}"}
    except Exception as e:
        sfs_result = {"erro": f"Erro de conexão: {str(e)}"}

    # --- 2. Consulta Google Safe Browsing (Domínio) ---
    gsb_result = verificar_dominio_gsb(domain)

    # --- 3. Verificação de MX (DNS) ---
    mx_result = verificar_mx(domain)

    return {
        "spam_db": sfs_result,
        "domain_security": gsb_result,
        "mx_records": mx_result
    }
