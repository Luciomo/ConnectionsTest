import subprocess
import platform
import re
import socket
import shutil

def extrair_host(url):
    """Remove protocolo e caminhos, deixando apenas o hostname ou IP."""
    if not url:
        return None
    host = re.sub(r'^https?://', '', url)
    host = host.split('/')[0]
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

def executar_tracert(url):
    """Executa tracert (Windows) ou traceroute (Linux)."""
    host = extrair_host(url)
    if not host:
        return {"erro": "Host inválido."}

    ipv4, ipv6 = resolve_ips(host)
    
    targets = []
    if ipv4: targets.append(("IPv4", ipv4))
    if ipv6: targets.append(("IPv6", ipv6))
    
    if not targets:
        targets.append(("Host", host))

    outputs = []
    sistema = platform.system().lower()
    
    # Define o nome base do comando dependendo do SO
    cmd_base = 'tracert' if sistema == 'windows' else 'traceroute'
    executable = cmd_base

    # Tenta localizar o executável absoluto se não estiver no PATH (Linux)
    if sistema != 'windows' and shutil.which(executable) is None:
        for path in [f'/usr/bin/{cmd_base}', f'/bin/{cmd_base}', f'/usr/sbin/{cmd_base}']:
            if shutil.which(path):
                executable = path
                break

    for label, target in targets:
        if sistema == 'windows':
            cmd = [executable, '-d', '-h', '15', target]
            encoding = 'cp850'
        else:
            cmd = [executable, '-n', '-m', '15', target]
            encoding = 'utf-8'

        try:
            # Adiciona um timeout de 60 segundos para evitar travamentos longos
            output_bytes = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=60)
            resultado = output_bytes.decode(encoding, errors='replace')
            outputs.append(f"=== {label} ({target}) ===\n{resultado}")
        except subprocess.TimeoutExpired:
            outputs.append(f"=== {label} ({target}) ===\nErro: Tempo limite de 60s excedido. O rastreamento demorou muito para responder.")
        except subprocess.CalledProcessError as e:
            output_erro = e.output.decode(encoding, errors='replace') if e.output else "Sem saída"
            outputs.append(f"=== {label} ({target}) ===\nFalha: {output_erro}")
        except FileNotFoundError:
            outputs.append(f"=== {label} ({target}) ===\nErro: Comando traceroute não encontrado.")
        except Exception as e:
            outputs.append(f"=== {label} ({target}) ===\nErro: {str(e)}")

    return {"output": "\n\n".join(outputs)}
