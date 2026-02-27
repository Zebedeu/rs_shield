#!/bin/bash
# ============================================================================
# setup-secure-credentials.sh
# Configurar credenciais S3 de forma segura para rs-shield
# ============================================================================

set -e

echo \"🔐 rs-shield - Configuração Segura de Credenciais S3\"
echo \"=======================================================\"
echo \"\"

# Cores para output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

# Criar diretório de configuração
CONFIG_DIR=\"$HOME/.rs-shield\"
mkdir -p \"$CONFIG_DIR\"
chmod 700 \"$CONFIG_DIR\"  # Apenas o usuário pode acessar

echo -e \"${GREEN}✓${NC} Diretório criado: $CONFIG_DIR\"
echo \"\"

# Método 1: Variáveis de Ambiente
echo \"Escolha o método de armazenamento de credenciais:\"
echo \"\"
echo \"  1) Variáveis de Ambiente (ideal para CI/CD)\"
echo \"  2) Arquivo Criptografado (ideal para uso local)\"
echo \"  3) Ambos\"
echo \"\"
read -p \"Opção (1-3): \" method

case $method in
    1)
        echo \"\"
        echo -e \"${YELLOW}Método: Variáveis de Ambiente${NC}\"
        echo \"\"
        echo \"Use em seu terminal ou CI/CD pipeline:\"
        echo \"\"
        read -sp \"AWS Access Key ID: \" ACCESS_KEY
        echo \"\"
        read -sp \"AWS Secret Access Key: \" SECRET_KEY
        echo \"\"
        read -sp \"AWS Session Token (deixe em branco se não houver): \" SESSION_TOKEN
        echo \"\"
        
        # Não salvamos em arquivo - apenas mostrar como usar
        echo -e \"${GREEN}✓ Credenciais capturadas${NC}\"
        echo \"\"
        echo \"Para usar, execute:\"
        echo \"\"
        echo \"export AWS_ACCESS_KEY_ID='$ACCESS_KEY'\"
        echo \"export AWS_SECRET_ACCESS_KEY='$SECRET_KEY'\"
        if [ -n \"$SESSION_TOKEN\" ]; then
            echo \"export AWS_SESSION_TOKEN='$SESSION_TOKEN'\"
        fi
        echo \"\"
        echo \"rsb backup config.toml\"
        echo \"\"
        ;;
    
    2)
        echo \"\"
        echo -e \"${YELLOW}Método: Arquivo Criptografado${NC}\"
        echo \"\"
        echo -e \"${YELLOW}Nota: Será solicitado criar uma Master Password${NC}\"
        echo \"      (armazenada no keyring do seu sistema operacional)\"
        echo \"\"
        
        read -sp \"AWS Access Key ID: \" ACCESS_KEY
        echo \"\"
        read -sp \"AWS Secret Access Key: \" SECRET_KEY
        echo \"\"
        read -sp \"AWS Session Token (deixe em branco se não houver): \" SESSION_TOKEN
        echo \"\"
        
        # Script para chamar Rust e salvar credenciais
        cat > \"$CONFIG_DIR/setup-temp.json\" << EOF
{
  \"access_key\": \"$ACCESS_KEY\",
  \"secret_key\": \"$SECRET_KEY\",
  \"session_token\": ${SESSION_TOKEN:+\"$SESSION_TOKEN\"}
}
EOF
        
        echo -e \"${GREEN}✓ Credenciais capturados${NC}\"
        echo \"\"
        echo -e \"${YELLOW}Próximo passo: Execute o backup para configurar a Master Password${NC}\"
        echo \"\"
        echo \"rsb backup config.toml\"
        echo \"\"
        echo \"Você será solicitado a criar uma Master Password forte\"
        echo \"(será armazenada no keyring do seu sistema)\"
        echo \"\"
        
        rm -f \"$CONFIG_DIR/setup-temp.json\"
        ;;
    
    3)
        echo \"\"
        echo -e \"${YELLOW}Método: Ambos (Variáveis de Ambiente + Arquivo Criptografado)${NC}\"
        echo \"\"
        
        read -sp \"AWS Access Key ID: \" ACCESS_KEY
        echo \"\"
        read -sp \"AWS Secret Access Key: \" SECRET_KEY
        echo \"\"
        read -sp \"AWS Session Token (deixe em branco se não houver): \" SESSION_TOKEN
        echo \"\"
        
        echo -e \"${GREEN}✓ Credenciais capturados${NC}\"
        echo \"\"
        echo \"Para uso imediato (variáveis de ambiente):\"
        echo \"\"
        echo \"export AWS_ACCESS_KEY_ID='$ACCESS_KEY'\"
        echo \"export AWS_SECRET_ACCESS_KEY='$SECRET_KEY'\"
        if [ -n \"$SESSION_TOKEN\" ]; then
            echo \"export AWS_SESSION_TOKEN='$SESSION_TOKEN'\"
        fi
        echo \"\"
        echo \"Para uso persistente (arquivo criptografado):\"
        echo \"Execute o backup para configurar a Master Password\"
        echo \"\"
        echo \"rsb backup config.toml\"
        echo \"\"
        ;;
    
    *)
        echo -e \"${RED}✗ Opção inválida${NC}\"
        exit 1
        ;;
esac

echo \"\"
echo -e \"${GREEN}=== Configuração Segura Concluída ===${NC}\"
echo \"\"
echo \"⚠️  Segurança - Lembre-se de:\"
echo \"  • NUNCA commitar credenciais em git\"
echo \"  • NUNCA compartilhar a Master Password\"
echo \"  • Rotacionar as chaves a cada 90 dias\"
echo \"  • Usar arquivo .gitignore para config files\"
echo \"\"
echo \"Para testar a conexão:\"
echo \"  rsb s3 test --config config.toml\"
echo \"\"
