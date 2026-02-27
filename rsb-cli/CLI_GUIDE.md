# 🚀 rsb-cli - Guia de Início Rápido

## Instalação

```bash
# Build do CLI
cargo build --release --bin rsb-cli

# Binário fica em:
./target/release/rsb-cli
```

---

## 📋 Uso Básico

### 1. Criar um Perfil de Backup

```bash
# Criar novo perfil
rsb create-profile myprofile /path/to/source /path/to/destination

# Isso gera um arquivo: myprofile.toml
```

### 2. Executar Backup

```bash
# Backup com config.toml (no diretório atual)
rsb backup config.toml

# Backup com arquivo específico
rsb backup /path/to/myprofile.toml

# Modo full (backup completo)
rsb backup config.toml full

# Dry-run (simula sem gravar)
rsb backup config.toml --dry-run

# Com relatório HTML
rsb backup config.toml --report
```

### 3. Restaurar Backup

```bash
# Restaurar snapshot mais recente
rsb restore config.toml

# Restaurar para diretório específico
rsb restore config.toml --target /path/to/restore

# Restaurar snapshot específico
rsb restore config.toml --snapshot snapshot-id-here

# Forçar sobrescrita
rsb restore config.toml --force
```

### 4. Verificar Integridade

```bash
# Verificar backup mais recente
rsb verify config.toml

# Verificar snapshot específico
rsb verify config.toml --snapshot snapshot-id

# Modo quiet (apenas erros)
rsb verify config.toml --quiet

# Verificação rápida (sem checksums)
rsb verify config.toml --fast
```

### 5. Prune (Limpeza)

```bash
# Remover snapshots antigos (manter últimos 30 dias)
rsb prune config.toml

# Manter apenas últimos N snapshots
rsb prune config.toml --keep 10

# Dry-run para ver o que seria deletado
rsb prune config.toml --dry-run
```

### 6. Sincronização em Tempo Real

```bash
# Monitorar diretório e sincronizar mudanças
rsb realtime --config config.toml --sync-to /destination --key "encryption-key"

# Com intervalo customizado (em segundos)
rsb realtime --config config.toml --sync-to /backup --key "key" --interval 5
```

---

## 🔐 Segurança - Credenciais S3

### Opção 1: Variáveis de Ambiente (Recomendado)

```bash
export AWS_ACCESS_KEY_ID="AKIA1234567890AB"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

rsb backup config.toml
```

### Opção 2: Arquivo Criptografado

```bash
# Primeira vez: Será solicitado criar Master Password
rsb backup config.toml

# Próximas vezes: Carrega automaticamente do arquivo criptografado
rsb backup config.toml
```

### Opção 3: Command-line (NÃO RECOMENDADO)

```bash
# Apenas para testes - evite em produção (histórico de shell)
rsb backup config.toml \
  --access-key AKIA1234567890AB \
  --secret-key your-secret-key
```

### Opção 4: Config File (DEPRECATED)

```toml
[s3]
access_key = "AKIA..."  # ❌ Evite - inseguro
secret_key = "secret..."  # ❌ Evite - inseguro
```

---

## 📁 Arquivo de Configuração (config.toml)

```toml
source_path = "/Users/usuario/Documents"
destination_path = "/backup/storage"
exclude_patterns = ["*.tmp", ".git/", "node_modules/"]
backup_mode = "incremental"
compression_level = 6
encrypt_patterns = ["*.pdf", "*.docx"]

# Opcional - thresholds de recurso
pause_on_low_battery = 20
pause_on_high_cpu = 80

# Opcional - S3
[s3]
bucket = "my-backup-bucket"
region = "us-east-1"
# Use env vars ou arquivo criptografado para credenciais!
```

---

## 🏥 Monitoramento com Healthchecks.io

```bash
# Enviar pings para healthchecks.io
rsb backup config.toml \
  --healthcheck-url "https://hc-ping.com/your-uuid-here"

# O comando envia:
# - /start: Quando começar
# - /success (vazio): Quando terminar com sucesso
# - /fail: Se houver erro
```

---

## 📊 Relatórios

```bash
# Gerar relatório HTML
rsb backup config.toml --report
# Cria: rsb-report-backup-20260208-120000.html

rsb restore config.toml --report
rsb verify config.toml --report
rsb prune config.toml --report
```

---

## 🔐 Criptografia

### Com Chave de Comando

```bash
rsb backup config.toml --key "my-secret-key"
rsb restore config.toml --key "my-secret-key"
```

### Entrada Interativa

```bash
# Será solicitado no terminal
rsb backup config.toml
# Digite a senha (não será echo'd)
```

---

## 🌍 S3 Compatível

O rs-shield suporta qualquer S3 compatível (MinIO, DigitalOcean, etc):

```toml
[s3]
bucket = "bucket-name"
region = "us-east-1"
endpoint = "https://minio.example.com"  # Customize endpoint
```

---

## 🆘 Troubleshooting

### "No such file or directory"
Verifique se o arquivo `config.toml` existe:
```bash
ls -la config.toml
# Se não existir, ou dentro do diretório especificado
```

### "Invalid TOML"
Verifique a sintaxe do seu arquivo `config.toml`. Campos obrigatórios:
- `source_path`
- `destination_path`
- `exclude_patterns` (pode ser array vazio: `[]`)
- `backup_mode` ("incremental" ou "full")

### "Permission denied"
Verificar permissões dos caminhos:
```bash
chmod 755 /path/to/source
chmod 755 /path/to/destination
```

### "S3 connection failed"
Verifique as credenciais:
```bash
# Confirmar que env vars estão definidas
echo $AWS_ACCESS_KEY_ID
echo $AWS_SECRET_ACCESS_KEY

# Ou testar o arquivo criptografado
rsb s3 test --config config.toml
```

---

## 📝 Exemplos Práticos

### Exemplo 1: Backup Simples Local

```bash
# config.toml
source_path = "/Users/eu/Documents"
destination_path = "/Volumes/backup"
exclude_patterns = [".git", "node_modules"]
backup_mode = "incremental"

# Executar
rsb backup config.toml
```

### Exemplo 2: S3 com Criptografia

```bash
# config.toml
source_path = "/Users/eu/Documents"
destination_path = "/tmp/staging"  # Staging local
exclude_patterns = []
backup_mode = "full"
encrypt_patterns = ["*.docx", "private/"]

[s3]
bucket = "my-secure-bucket"
region = "us-east-1"

# Com credenciais em env vars
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

rsb backup config.toml --key "strong-password" --report
```

### Exemplo 3: Backup Agendado (Cron)

```bash
# Adicionar ao crontab
0 2 * * * cd /path/to/project && ./target/release/rsb-cli backup config.toml >> backup.log 2>&1

# Ou com integridade
0 2 * * * cd /path/to/project && ./target/release/rsb-cli backup config.toml --report && grep -i error backup.log || mail -s "Backup ok" admin@example.com
```

### Exemplo 4: Sincronização em Tempo Real

```bash
# Terminal 1: Iniciar sync
rsb realtime \
  --config config.toml \
  --sync-to /path/to/sync \
  --key "encryption-key" \
  --interval 5

# Terminal 2: Fazer mudanças em source_path
# Automaticamente será sincronizado a cada 5 segundos
```

---

## 🎯 Checklist de Setup

- [ ] Build do projeto: `cargo build --release`
- [ ] Arquivo config.toml criado
- [ ] Caminhos verificados (source_path, destination_path)
- [ ] Primeiro backup executado com sucesso
- [ ] Restauração testada
- [ ] Se S3: credenciais configuradas (env vars)
- [ ] Se criptografia: chave backup securing
- [ ] Agendamento setup (se desejado)

---

## 📞 Próximos Passos

1. Ler [SECURITY_CREDENTIALS.md](SECURITY_CREDENTIALS.md) para proteger credenciais S3
2. Configurar agendamento (cron/systemd)
3. Habilitar monitoramento (healthchecks.io)
4. Testar restauração regularmente

**Backup seguro = Dados seguros!** 🛡️
