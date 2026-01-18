#!/bin/bash
# Redireciona a saída para um arquivo de log para facilitar a depuração em caso de erro
# O log ficará disponível em: /var/log/user-data.log
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "🚀 Iniciando configuração automática da instância..."

# 1. Atualização do Sistema e Instalação de Dependências (Amazon Linux 2023)
dnf update -y
dnf install -y python3 python3-pip git whois traceroute iputils libcap

# 2. Preparação do Diretório da Aplicação
mkdir -p /home/ec2-user/app
chown ec2-user:ec2-user /home/ec2-user/app
cd /home/ec2-user/app

# 3. Obtenção do Código Fonte
# ⚠️ IMPORTANTE: Substitua a URL abaixo pelo seu repositório GitHub
# Se o repositório for privado, use o formato: https://usuario:token_pessoal@github.com/usuario/repo.git
echo "📥 Clonando repositório..."
sudo -u ec2-user git clone https://github.com/seu-usuario/VerificaZap.git .

# 4. Configuração do Ambiente Python
echo "🐍 Configurando Python Venv..."
sudo -u ec2-user python3 -m venv venv
sudo -u ec2-user ./venv/bin/pip install -r requirements.txt

# Permite que o Python abra sockets raw (necessário para o ping3 funcionar sem root)
setcap cap_net_raw+ep /home/ec2-user/app/venv/bin/python3

# 5. Criação do arquivo de variáveis de ambiente (.env)
# ⚠️ IMPORTANTE: Substitua os valores abaixo pelas suas chaves reais antes de usar no EC2
echo "🔑 Configurando variáveis de ambiente..."
cat <<EOF > .env
VT_API_KEY=sua_chave_do_virustotal_aqui
GSB_API_KEY=sua_chave_do_google_safe_browsing_aqui
EOF
chown ec2-user:ec2-user .env

# 6. Configuração do Systemd (Para rodar o Gunicorn como serviço)
echo "⚙️ Configurando Systemd..."
cat <<EOF > /etc/systemd/system/connections-test.service
[Unit]
Description=Gunicorn instance to serve ConnectionsTest
After=network.target

[Service]
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user/app
Environment="PATH=/home/ec2-user/app/venv/bin:/usr/local/bin:/usr/bin:/bin"
EnvironmentFile=/home/ec2-user/app/.env
ExecStart=/home/ec2-user/app/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5500 --timeout 120 app:app
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 7. Iniciar Serviço
systemctl daemon-reload
systemctl start connections-test
systemctl enable connections-test

echo "✅ Deploy concluído! A aplicação deve estar rodando na porta 5500 via Systemd."
