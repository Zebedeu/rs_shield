# RSB CLI (Command Line Interface)

The official command line interface for **Rust Shield Backup**. Designed for automation, servers, and advanced users who prefer the terminal.

## 🚀 Installation

```bash
cargo install --path .
```

## 📖 Comandos Disponíveis

### 1. Criar Perfil
Gera um arquivo de configuração `config.toml` inicial.

```bash
rsb create-profile "meu-backup" "/home/user/docs" "/mnt/backup"
```

### 2. Executar Backup
Realiza o backup com base no perfil.

```bash
rsb backup config.toml --key "minha-senha"
```
- `--dry-run`: Simula o backup sem gravar dados.
- `--mode full`: Força um backup completo (padrão é incremental).
- `--report`: Gera um relatório HTML ao final.

### 3. Restaurar (Restore)
Recupera arquivos de um snapshot.

```bash
rsb restore config.toml --target "/home/user/restored" --key "minha-senha"
```
- `--snapshot <ID>`: Restaura um snapshot específico (padrão: último).
- `--force`: Sobrescreve arquivos existentes.

### 4. Monitoramento em Tempo Real (Watch)
Monitora uma pasta e sincroniza/backup automaticamente a cada alteração.

```bash
rsb watch config.toml --sync-to "/pasta/sync" --key "senha" --interval 2
```
- Ideal para manter duas pastas sincronizadas e gerar histórico de versões (backups) simultaneamente.

### 5. Agendamento (Schedule)
Gera comandos para agendadores de tarefas do sistema.

```bash
rsb schedule config.toml --format cron
# Ou para systemd
rsb schedule config.toml --format systemd
```

### 6. Manutenção (Prune & Verify)

**Verificar integridade:**
```bash
rsb verify config.toml --fast
```
- `--fast`: Verifica apenas tamanho e hash armazenado (sem desencriptar).
- Sem flag: Verifica integridade completa (desencripta e recalcula hash).

**Limpar backups antigos:**
```bash
rsb prune config.toml --keep-last 5
```
- Mantém apenas os 5 snapshots mais recentes e remove dados órfãos.

## 🔐 Gerenciamento de Credenciais S3

O RSB CLI busca credenciais na seguinte ordem de prioridade:
1. **Keyring do Sistema** (Recomendado/Seguro).
2. **Variáveis de Ambiente** (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).
3. **Argumentos da CLI** (`--access-key`, `--secret-key`) (Não recomendado para produção).
4. **Prompt Interativo** (Se não encontradas, solicita ao usuário).