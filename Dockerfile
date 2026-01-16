FROM python:3.12-slim

# Instala utilitários de sistema necessários
# iputils-ping: fornece o comando ping
# traceroute: fornece o comando traceroute
# whois: fornece o comando whois
# ca-certificates: necessário para requisições HTTPS (speedtest, APIs)
RUN apt-get update && \
    apt-get install -y iputils-ping traceroute whois ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copia e instala dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY . .

# Expõe a porta que a aplicação usará
EXPOSE 5500

# Comando de execução em produção usando Gunicorn
# Workers = 2 * núcleos + 1 (ajuste conforme a instância EC2)
CMD ["gunicorn", "--bind", "0.0.0.0:5500", "--workers", "3", "--timeout", "120", "app:app"]