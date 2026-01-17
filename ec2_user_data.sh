#!/bin/bash
# Redireciona a saída para um arquivo de log para facilitar a depuração em caso de erro
# O log ficará disponível em: /var/log/user-data.log
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "🚀 Iniciando configuração automática da instância..."

# 1. Atualização do Sistema e Instalação de Dependências (Amazon Linux 2023)
dnf update -y
dnf install -y docker git

# 2. Configuração e Inicialização do Docker
systemctl start docker
systemctl enable docker
# Adiciona o usuário padrão 'ec2-user' ao grupo docker para facilitar acesso via SSH depois
usermod -aG docker ec2-user

# 3. Preparação do Diretório da Aplicação
mkdir -p /home/ec2-user/app
cd /home/ec2-user/app

# 4. Obtenção do Código Fonte
# ⚠️ IMPORTANTE: Substitua a URL abaixo pelo seu repositório GitHub
# Se o repositório for privado, use o formato: https://usuario:token_pessoal@github.com/usuario/repo.git
echo "📥 Clonando repositório..."
git clone https://Luciomo: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@github.com/Luciomo/ConnectionsTest.git

# 5. Criação do arquivo de variáveis de ambiente (.env)
# ⚠️ IMPORTANTE: Substitua os valores abaixo pelas suas chaves reais antes de usar no EC2
echo "🔑 Configurando variáveis de ambiente..."
cat <<EOF > .env
VT_API_KEY=b2e21b6cfb0e32f3ea049d3077afa4aac321cf22481af3c430cc003eaee4295e
GSB_API_KEY=AIzaSyDutddvVDU7maS1Hj6FrQcEWvYCYCAi0B0
EOF

# 6. Execução da Aplicação com Docker Compose
# O Amazon Linux 2023 geralmente já traz o plugin compose, mas garantimos a instalação
dnf install -y docker-compose-plugin

echo "🐳 Subindo containers..."
# --build: garante que a imagem seja construída localmente
# -d: roda em background (detached)
docker compose up -d --build

echo "✅ Deploy concluído! A aplicação deve estar rodando na porta 5500."
echo "Não esqueça de liberar a porta 5500 no Security Group da EC2."
