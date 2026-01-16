import subprocess
import platform
import re
import socket

def extrair_host(url):
    """Remove protocolo e caminhos, deixando apenas o hostname ou IP."""
    if not url:
        return None
    # Remove http:// ou https://
    host = re.sub(r'^https?://', '', url)
    # Remove caminhos após o domínio (ex: .com/pagina -> .com)
    host = host.split('/')[0]
    # Remove porta se houver
    host = host.split(':')[0]
    return host

def resolve_ips(host):
    """Tenta resolver o host para obter IPs v4 e v6."""
    ipv4 = None
    ipv6 = None
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            if info[0] == socket.AF_INET:
                ipv4 = info[4][0]
            elif info[0] == socket.AF_INET6:
                ipv6 = info[4][0]
    except:
        pass
    return ipv4, ipv6

def executar_ping(url):
    """Executa o comando ping no sistema operacional."""
    host = extrair_host(url)
    if not host:
        return {"erro": "Host inválido."}

    ipv4, ipv6 = resolve_ips(host)
    
    # Lista de alvos para pingar. Se tiver IPv4 e IPv6, pinga ambos.
    targets = []
    if ipv4: targets.append(("IPv4", ipv4))
    if ipv6: targets.append(("IPv6", ipv6))
    
    # Se não resolveu (ex: erro DNS ou host inválido), tenta o original como fallback
    if not targets:
        targets.append(("Host", host))

    outputs = []
    sistema = platform.system().lower()

    for label, target in targets:
        if sistema == 'windows':
            cmd = ['ping', '-n', '4', target]
            encoding = 'cp850'
        else:
            cmd = ['ping', '-c', '4', target]
            encoding = 'utf-8'

        try:
            output_bytes = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            resultado = output_bytes.decode(encoding, errors='replace')
            outputs.append(f"=== {label} ({target}) ===\n{resultado}")
        except subprocess.CalledProcessError as e:
            output_erro = e.output.decode(encoding, errors='replace') if e.output else "Sem saída"
            outputs.append(f"=== {label} ({target}) ===\nFalha: {output_erro}")
        except Exception as e:
            outputs.append(f"=== {label} ({target}) ===\nErro: {str(e)}")

    return {"output": "\n\n".join(outputs)}