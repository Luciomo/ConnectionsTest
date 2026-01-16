#!/bin/python3

import time
import statistics
from ping3 import ping
import speedtest

def measure_latency(target_ip, count=10):
    latencies = []
    for _ in range(count):
        latency = ping(target_ip, unit='ms')
        if latency:
            latencies.append(latency)
        time.sleep(1)
    return latencies

def calculate_jitter(latencies):
    if len(latencies) < 2:
        return 0
    diffs = [abs(latencies[i] - latencies[i - 1]) for i in range(1, len(latencies))]
    return statistics.mean(diffs)

def measure_throughput():
    st = speedtest.Speedtest()
    st.download()
    st.upload()
    results = st.results.dict()
    return results["download"] / 1_000_000, results["upload"] / 1_000_000  # Convert to Mbps

def main():
    target_ip = input("Digite o IP alvo para medir latência e jitter: ")
    latencies = measure_latency(target_ip)
    jitter = calculate_jitter(latencies)
    download_speed, upload_speed = measure_throughput()

    if latencies:
        average_latency = statistics.mean(latencies)
    else:
        average_latency = 0

    print(f"Latência (ms): {latencies}")
    print(f"Média de Latência (ms): {average_latency:.2f}")
    print(f"Jitter (ms): {jitter:.2f}")
    print(f"Velocidade de download (Mbps): {download_speed:.2f}")
    print(f"Velocidade de upload (Mbps): {upload_speed:.2f}")

if __name__ == "__main__":
    main()