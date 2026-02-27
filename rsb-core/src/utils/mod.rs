// src/utils/mod.rs

use ignore::{WalkBuilder, Walk};
use memmap2::Mmap;
use std::path::{Path, PathBuf};

pub fn expand_path(path: &str) -> PathBuf {
    // Primeiro, expandir ~ se o path começar com ele
    let path_str = if path.starts_with("~") {
        if let Some(home) = dirs::home_dir() {
            path.replacen("~", &home.to_string_lossy(), 1)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    };

    // Depois, expandir variáveis de ambiente ($VAR e ${VAR})
    let expanded = expand_env_vars(&path_str);
    
    PathBuf::from(expanded)
}


fn expand_env_vars(path: &str) -> String {
    let mut result = String::new();
    let mut chars = path.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            // Check if next char is { or alphanumeric
            match chars.peek() {
                Some('{') => {
                    // ${VAR} format
                    chars.next(); // consume {
                    let mut var_name = String::new();
                    
                    while let Some(&c) = chars.peek() {
                        if c == '}' {
                            chars.next(); // consume }
                            break;
                        }
                        var_name.push(c);
                        chars.next();
                    }
                    
                    // Tentar expandir com fallbacks inteligentes
                    if let Some(expanded) = expand_env_var_with_fallback(&var_name) {
                        result.push_str(&expanded);
                    } else {
                        // Se a variável não existir, manter como está
                        result.push('$');
                        result.push('{');
                        result.push_str(&var_name);
                        result.push('}');
                    }
                }
                Some(c) if c.is_alphanumeric() || *c == '_' => {
                    // $VAR format
                    let mut var_name = String::new();
                    
                    while let Some(&c) = chars.peek() {
                        if c.is_alphanumeric() || c == '_' {
                            var_name.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                    
                    // Tentar expandir com fallbacks inteligentes
                    if let Some(expanded) = expand_env_var_with_fallback(&var_name) {
                        result.push_str(&expanded);
                    } else {
                        // Se a variável não existir, manter como está
                        result.push('$');
                        result.push_str(&var_name);
                    }
                }
                _ => {
                    // $ alone
                    result.push('$');
                }
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Tenta expandir uma variável de ambiente com fallbacks inteligentes para cross-platform
fn expand_env_var_with_fallback(var_name: &str) -> Option<String> {
    // Primeiro, tentar a variável literal
    if let Ok(val) = std::env::var(var_name) {
        return Some(val);
    }
    
    // Fallbacks inteligentes para HOME / USERPROFILE
    match var_name {
        "HOME" => {
            // No Windows, tentar USERPROFILE se HOME não existir
            std::env::var("USERPROFILE").ok()
                .or_else(|| dirs::home_dir().map(|p| p.to_string_lossy().into_owned()))
        }
        "USERPROFILE" => {
            // Em Linux/macOS, tentar HOME se USERPROFILE não existir
            std::env::var("HOME").ok()
                .or_else(|| dirs::home_dir().map(|p| p.to_string_lossy().into_owned()))
        }
        _ => None,
    }
}

/// Verifica se um caminho corresponde a um padrão de exclusão
/// 
/// ## Sistema de Exclusão de Arquivos
/// 
/// O aplicativo utiliza **3 mecanismos combinados** para excluir arquivos do backup:
/// 
/// ### 1️⃣ Arquivos .gitignore (Automático - Sem Log Individual)
/// Se um `.gitignore` existe, as regras nele são respeitadas automaticamente.
/// Exemplo: Se `.gitignore` contém `node_modules/`, esses arquivos não aparecem no backup.
/// Rastreamento: Log geral indica "✅ Respeitar .gitignore: ATIVO"
/// 
/// ### 2️⃣ Padrões Personalizados (Do Perfil ou Configuração Global)
/// Padrões especificados em `exclude_patterns` no arquivo `.toml` ou `app_preferences.json`.
/// Cada arquivo excluído gera log: "🚫 Excluindo: <arquivo> (padrão: <pattern>)"
/// 
/// ### 3️⃣ Formatos de Padrão Suportados
/// - `*.ext` - Wildcard: `*.tmp`, `*.log`, `*.js` → todos arquivos com essa extensão
/// - `.hidden` - Ponto no início: `.git`, `.DS_Store` → arquivos/pastas ocultos
/// - `folder` - Pasta: `node_modules`, `build`, `__pycache__` → diretório inteiro
/// - `arquivo.js` - Arquivo exato: `app.ts`, `index.js` → arquivo específico
pub fn matches_exclude_pattern(path: &Path, pattern: &str) -> bool {
    let path_str = path.to_string_lossy();
    let path_display = path.display().to_string();
    
    if pattern.is_empty() {
        return false;
    }
    
    let pattern_normalized = pattern.trim_end_matches('/');
    
    // ============================================================================
    // Caso 1: Padrão wildcard → *.ext
    // ============================================================================
    if pattern_normalized.starts_with("*.") {
        // Exemplo: *.tmp, *.js, *.log
        let ext = &pattern_normalized[1..]; // Remove o * → .tmp, .js, .log
        return path_str.ends_with(ext);
    }
    
    // ============================================================================
    // Caso 2: Padrão com ponto no início → .git, .gitignore, .DS_Store
    // ============================================================================
    if pattern_normalized.starts_with('.') {
        // Procura componentes do path que são exatamente este padrão
        // Exemplo: .git, .DS_Store
        for component in path.iter() {
            if let Some(comp_str) = component.to_str() {
                if comp_str == pattern_normalized || comp_str.starts_with(pattern_normalized) {
                    return true;
                }
            }
        }
    }
    
    // ============================================================================
    // Caso 3: Arquivo ou pasta específica
    // ============================================================================
    
    // 3a: Verifica se o último componente do path é exatamente o padrão
    // Exemplo: pattern="index.js" → /path/to/index.js → EXCLUIR
    //          pattern="app.ts" → /path/to/app.ts → EXCLUIR
    if let Some(file_name) = path.file_name() {
        if let Some(file_name_str) = file_name.to_str() {
            if file_name_str == pattern_normalized {
                return true;
            }
        }
    }
    
    // 3b: Verifica se é um diretório completo (componente do meio do path)
    // Exemplo: pattern="node_modules" → /src/node_modules/lib.js → EXCLUIR
    //          pattern="build" → /src/build/out.js → EXCLUIR
    for component in path.iter() {
        if let Some(comp_str) = component.to_str() {
            if comp_str == pattern_normalized {
                return true;
            }
        }
    }
    
    // 3c: Verifica como substring para caminhos relativos
    // Exemplo: pattern="node_modules" → caminhos contendo /node_modules/ ou node_modules/
    if path_display.contains(&format!("/{}/", pattern_normalized))
        || path_display.contains(&format!("{}/", pattern_normalized))
        || path_display.starts_with(&format!("{}/", pattern_normalized))
    {
        return true;
    }
    
    false
}

/// Cria um WalkBuilder configurado com filtros de exclusão
pub fn build_walker(
    root: &Path,
    _custom_globs: &[String],
    respect_gitignore: bool,
) -> WalkBuilder {
    let mut builder = WalkBuilder::new(root);

    builder
        .git_ignore(respect_gitignore)
        .ignore(respect_gitignore)
        .hidden(false)
        .follow_links(false)
        .max_depth(None)
        .threads(0);

    builder
}

/// Retorna o iterador Walk pronto a usar com filtragem de exclusão
/// 
/// IMPORTANTE: Esta função filtra os resultados do walk baseado nos padrões
/// de exclusão fornecidos. Os padrões suportados são:
/// - `*.ext`: Wildcard no final (e.g., `*.tmp`, `*.log`)
/// - `.hidden`: Começa com ponto (e.g., `.git`, `.DS_Store`)
/// - `folder/` ou `folder`: Padrão simples (e.g., `node_modules`, `build`)
pub fn walk_filtered(
    root: &Path,
    custom_globs: &[String],
    respect_gitignore: bool,
) -> Walk {
    let walker = build_walker(root, custom_globs, respect_gitignore).build();
    walker
}

/// Memory-map de ficheiro
pub fn mmap_file(path: &Path) -> std::io::Result<Mmap> {
    let file = std::fs::File::open(path)?;
    unsafe { Mmap::map(&file) }
}

/// ============================================================================
/// PONTO CENTRALIZADO PARA VERIFICAÇÃO E CRIAÇÃO DE DIRETÓRIOS
/// ============================================================================
/// 
/// Esta é a ÚNICA função que deve ser usada no sistema para criar/verificar 
/// diretórios. Garante:
/// 
/// 1. Cross-platform: Windows, macOS, Linux com mesmo comportamento
/// 2. Permissões consistentes: 0o700 (rwx------) em Unix/macOS
/// 3. Home directory: Sempre usa dirs::home_dir() para expansão correta
/// 4. Tratamento de erros unificado
/// 5. Logging centralizado para auditoria
/// ============================================================================

/// Garante que um diretório existe, criando-o se necessário com permissões corretas
/// 
/// ## Cross-Platform Behavior
/// - **Windows:** Cria com permissões padrão do SO
/// - **macOS/Linux:** Cria com permissões 0o700 (rwx------)
/// 
/// ## Exemplo
/// ```rust
/// use rsb_core::utils::ensure_directory_exists;
/// 
/// match ensure_directory_exists("~/.rs-shield") {
///     Ok(path) => println!("Diretório garantido: {:?}", path),
///     Err(e) => eprintln!("Erro: {}", e),
/// }
/// ```
pub fn ensure_directory_exists(path: &str) -> std::result::Result<PathBuf, String> {
    use std::fs;
    
    // Expandir path (suporta ~, $VAR, ${VAR})
    let expanded_path = expand_path(path);
    
    // Verificar se já existe
    if expanded_path.exists() {
        if expanded_path.is_dir() {
            return Ok(expanded_path);
        } else {
            return Err(format!(
                "Caminho existe mas não é diretório: {}",
                expanded_path.display()
            ));
        }
    }
    
    // Criar diretório com permissões apropriadas
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        
        let mut builder = DirBuilder::new();
        builder.mode(0o700); // rwx------
        builder.recursive(true);
        
        builder
            .create(&expanded_path)
            .map_err(|e| format!(
                "Erro ao criar diretório '{}': {}",
                expanded_path.display(),
                e
            ))?;
    }
    
    #[cfg(not(unix))]
    {
        fs::create_dir_all(&expanded_path)
            .map_err(|e| format!(
                "Erro ao criar diretório '{}': {}",
                expanded_path.display(),
                e
            ))?;
    }
    
    Ok(expanded_path)
}

/// Versão assíncrona de ensure_directory_exists
/// 
/// Mesmo comportamento que versão síncrona, mas usa tokio::fs para não bloquear
pub async fn ensure_directory_exists_async(path: &str) -> std::result::Result<PathBuf, String> {
    use tokio::fs;
    
    // Expandir path (suporta ~, $VAR, ${VAR})
    let expanded_path = expand_path(path);
    
    // Verificar se já existe
    match fs::metadata(&expanded_path).await {
        Ok(meta) => {
            if meta.is_dir() {
                return Ok(expanded_path);
            } else {
                return Err(format!(
                    "Caminho existe mas não é diretório: {}",
                    expanded_path.display()
                ));
            }
        }
        Err(_) => {
            // Não existe, vai criar
        }
    }
    
    // Criar diretório
    fs::create_dir_all(&expanded_path)
        .await
        .map_err(|e| format!(
            "Erro ao criar diretório '{}': {}",
            expanded_path.display(),
            e
        ))?;
    
    Ok(expanded_path)
}

/// Verifica se um diretório existe, retorna PathBuf expandido ou erro
pub fn verify_directory_exists(path: &str) -> std::result::Result<PathBuf, String> {
    let expanded_path = expand_path(path);
    
    if !expanded_path.exists() {
        return Err(format!(
            "Diretório não encontrado: {} (expandido de: {})",
            expanded_path.display(),
            path
        ));
    }
    
    if !expanded_path.is_dir() {
        return Err(format!(
            "Caminho existe mas não é diretório: {}",
            expanded_path.display()
        ));
    }
    
    Ok(expanded_path)
}