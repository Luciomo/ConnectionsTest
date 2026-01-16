import time
import statistics
from ping3 import ping
import speedtest

def measure_latency(target_ip, count=4):
    """Mede a latência enviando pings ICMP."""
    latencies = []
    error_msg = None
    try:
        for _ in range(count):
            # Timeout de 2s para não travar muito
            latency = ping(target_ip, unit='ms', timeout=2)
            if latency is not None:
                latencies.append(latency)
            time.sleep(0.5)
    except PermissionError:
        error_msg = "Permissão negada. Execute como Administrador para usar ping ICMP."
    except Exception as e:
        error_msg = str(e)
    
    return latencies, error_msg

def calculate_jitter(latencies):
    """Calcula o Jitter baseado na variação das latências."""
    if not latencies or len(latencies) < 2:
        return 0
    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return statistics.mean(diffs)

def measure_throughput():
    """Mede velocidades de Download e Upload."""
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download() / 1_000_000  # Convert to Mbps
        upload = st.upload() / 1_000_000      # Convert to Mbps
        return download, upload, None
    except Exception as e:
        return 0, 0, str(e)

def executar_teste_conexao(target_ip):
    """Orquestra os testes de conexão."""
    result = {}
    
    # 1. Latência e Jitter
    latencies, lat_error = measure_latency(target_ip)
    if lat_error:
        result['latency_error'] = lat_error
    elif latencies:
        result['avg_latency'] = statistics.mean(latencies)
        result['jitter'] = calculate_jitter(latencies)
    else:
        result['latency_error'] = "Não foi possível obter resposta do alvo (Timeout ou Bloqueio)."

    # 2. Velocidade (Speedtest)
    download, upload, st_error = measure_throughput()
    result['download'] = download
    result['upload'] = upload
    result['speedtest_error'] = st_error

    return result