/**
 * =============================================================================
 * securityModule.js - Módulo de Segurança Client-Side Essencial (KISS)
 * =============================================================================
 * Implementa proteções fundamentais de segurança front-end seguindo a filosofia
 * KISS (Keep It Simple, Stupid). Fornece ferramentas essenciais para:
 * - Prevenção de XSS (Cross-Site Scripting)
 * - Configuração automática de CSP (Content Security Policy)
 * - Carregamento seguro de scripts externos com SRI
 * - Sanitização e validação de entrada de dados
 * - Suporte a Trusted Types para navegadores modernos
 * 
 * Aviso: Esta função é auto-executável e aplica CSP imediatamente.
 * Posicione este script no <head> antes de qualquer outro script.
 * =============================================================================
 */

/**
 * Mapa de caracteres para escapar em conteúdo HTML.
 * Cada caractere especial é mapeado para sua entidade HTML correspondente.
 * @private
 */
const HTML_ESCAPE_MAP = {
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;',
    "'": '&#39;', '`': '&#96;', '/': '&#47;', // Usando Hex consistente
    // Substitui LS/PS por espaço para prevenir quebra de strings JS e ataques baseados em caracteres Unicode
    '\u2028': ' ', // Line Separator - pode quebrar strings JS e causar XSS se não tratado
    '\u2029': ' '  // Paragraph Separator - mesmo problema do LS
};

/**
 * Escapa caracteres HTML especiais e separadores de linha/parágrafo Unicode.
 * Função fundamental para prevenção de XSS em conteúdo dinâmico.
 * 
 * @param {*} input - A entrada a ser escapada (qualquer tipo)
 * @returns {string} - String segura para uso em contextos HTML
 */
function escapeHtml(input) {
    const str = String(input ?? ''); // Converte para string e trata null/undefined
    return str.replace(/[&<>"'`/\u2028\u2029]/g, c => HTML_ESCAPE_MAP[c]);
}

/**
 * Converte a entrada para um número (float) finito ou retorna null se inválido.
 * Usa validação rigorosa que rejeita strings parciais como "123abc".
 * 
 * @param {*} input - A entrada a ser convertida para número
 * @returns {number | null} - Número validado ou null se inválido
 */
function cleanNumber(input) {
    const strInput = String(input ?? '').trim();
    if (strInput === '') return null;
    
    // Regex rigorosa exige que a string INTEIRA corresponda ao formato numérico
    const numberPattern = /^[+-]?(\d*\.?\d+|\d+\.?)$/;
    if (!numberPattern.test(strInput)) return null;
    
    const num = parseFloat(strInput);
    return !isNaN(num) && isFinite(num) ? num : null;
}

/**
 * Limpa texto: remove espaços das extremidades e limita o comprimento.
 * Intencionalmente simples para alta performance e casos de uso comuns.
 * 
 * @param {*} input - A entrada a ser limpa
 * @param {number} [maxLength=1000] - Comprimento máximo permitido
 * @returns {string} - Texto limpo
 */
function cleanText(input, maxLength = 1000) {
    return String(input ?? '').trim().substring(0, maxLength);
}

/**
 * Gera um nonce criptograficamente seguro (32 bytes / 256 bits).
 * Usado para CSP e outras necessidades de tokens seguros.
 * 
 * @private
 * @returns {string} - Nonce em formato hexadecimal ou 'CRYPTO_ERROR' em caso de falha
 */
function generateNonce() {
    const buffer = new Uint8Array(32); // 256 bits de entropia
    try {
        window.crypto.getRandomValues(buffer);
        return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        console.error("SECURITY MODULE: Falha crítica - crypto.getRandomValues indisponível/falhou.", e);
        return 'CRYPTO_ERROR'; // Indicador de falha explícito
    }
}

/**
 * Aplica Content Security Policy (CSP) via meta tag automaticamente.
 * Configurada para bloquear a maioria dos vetores XSS comuns.
 * 
 * @private
 */
function applyBasicCSP() {
    // Evita aplicar CSP duplicada
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;
    
    // Gera nonces únicos para script e style
    const scriptNonce = generateNonce();
    const styleNonce = generateNonce();
    
    // Aborta silenciosamente se a geração de nonce falhar
    if (scriptNonce === 'CRYPTO_ERROR' || styleNonce === 'CRYPTO_ERROR') return;

    // Política CSP balanceando segurança e usabilidade
    const cspPolicy = [
        "default-src 'none'",                                              // Bloqueia tudo por padrão
        "script-src 'self' 'strict-dynamic' 'nonce-" + scriptNonce + "'",  // Scripts com nonce
        "style-src 'self' 'nonce-" + styleNonce + "' https://fonts.googleapis.com", // Estilos com nonce
        "font-src 'self' https://fonts.gstatic.com",                       // Fontes permitidas
        "img-src 'self' https:",                                           // Imagens HTTPS
        "connect-src 'self'",                                              // Conexões Ajax/fetch
        "form-action 'self'",                                              // Submissões de formulário
        "base-uri 'none'",                                                 // Previne ataques base-uri
        "frame-ancestors 'none'",                                          // Previne clickjacking
        "object-src 'none'",                                               // Bloqueia objetos/embeds
    ].join('; ');
    
    // Aplica a CSP via meta tag
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = cspPolicy;
    
    if (document.head) {
         document.head.prepend(meta);
    } else {
         console.error("SECURITY MODULE: Falha ao aplicar CSP - document.head não encontrado.");
    }
}

/**
 * Define cookie com atributos de segurança essenciais.
 * Aplica automaticamente SameSite=Strict e Secure (em HTTPS).
 * 
 * @param {string} name - Nome do cookie (não pode ser vazio)
 * @param {*} value - Valor a ser armazenado
 * @param {number} [days=7] - Duração em dias (0 para sessão)
 * @param {string} [path='/'] - Path do cookie (deve começar com '/')
 */
export function setSecureCookie(name, value, days = 7, path = '/') {
    // Validações de segurança nos parâmetros
    if (typeof name !== 'string' || name.trim() === '') {
        console.error('SECURITY MODULE: Nome do cookie inválido.');
        return;
    }
    
    // Rejeita valores undefined/null por segurança
    if (value === undefined || value === null) {
       console.error('SECURITY MODULE: Valor do cookie inválido (undefined/null).');
       return;
    }
    
    // Valida e corrige path se necessário
    if (typeof path !== 'string' || !path.startsWith('/')) {
       console.warn(`SECURITY MODULE: Path do cookie inválido ('${path}'). Usando '/'.`);
       path = '/';
    }
    
    // Configura expiração se dias > 0
    let expiresAttribute = '';
    if (days && typeof days === 'number' && days > 0) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expiresAttribute = `; expires=${date.toUTCString()}`;
    }
    
    // Adiciona Secure apenas em HTTPS
    const secureAttribute = window.location.protocol === 'https:' ? '; Secure' : '';
    
    // Define o cookie com todos os atributos de segurança
    document.cookie = `${name}=${encodeURIComponent(String(value))}${expiresAttribute}; path=${path}${secureAttribute}; SameSite=Strict`;
    /* Nota: Configure HttpOnly no servidor para máxima proteção! */
}

/**
 * Rastreia scripts já carregados para prevenir duplicação.
 * @private @type {Set<string>}
 */
const loadedScripts = new Set();

/**
 * Verifica se a URL tem protocolo seguro permitido.
 * Aceita apenas HTTPS e caminhos relativos.
 * 
 * @private
 * @param {string} src - URL a verificar
 * @returns {boolean} - true se protocolo for seguro
 */
function isAllowedProtocol(src) {
    return src.startsWith('https://') || src.startsWith('/') || src.startsWith('./') || src.startsWith('../');
}

/**
 * Carrega script externo com verificações de segurança:
 * - Validação de protocolo
 * - Suporte a SRI (Subresource Integrity)
 * - Controle CORS
 * - Fallback automático
 *
 * @param {string} src - URL do script principal (HTTPS ou relativa)
 * @param {object} [options={}] - Opções de carregamento
 * @param {string|null} [options.integrity=null] - Hash SRI (sha256/384/512)
 * @param {string|null} [options.crossorigin=null] - Modo CORS ('anonymous'/'use-credentials')
 * @param {string|null} [options.fallbackSrc=null] - URL alternativa se principal falhar
 */
export function loadExternalScript(src, options = {}) {
    const { integrity = null, crossorigin = null, fallbackSrc = null } = options;

    // Validações de segurança
    if (!src || typeof src !== 'string') {
         console.error('SECURITY MODULE: URL do script inválida fornecida.');
        return;
    }
    
    if (!isAllowedProtocol(src)) {
        console.error(`SECURITY MODULE: Protocolo não permitido para script src: ${src}.`);
        return;
    }
    
    // Validação do fallback
    let validFallbackSrc = fallbackSrc;
    if (fallbackSrc && typeof fallbackSrc === 'string' && !isAllowedProtocol(fallbackSrc)) {
         console.error(`SECURITY MODULE: Protocolo não permitido para fallback: ${fallbackSrc}.`);
         validFallbackSrc = null;
    }
    
    // Evita carregamento duplicado
    if (loadedScripts.has(src)) return;
    loadedScripts.add(src);

    // Define crossOrigin automático se integrity presente e crossorigin não especificado
    const crossOriginAttr = integrity ? (crossorigin || 'anonymous') : crossorigin;

    // Alerta sobre carregamentos externos sem SRI (risco de segurança)
    if (!integrity && src.startsWith('https://')) {
        console.warn(`SECURITY MODULE: Carregando script externo sem SRI: ${src}`);
    }

    // Cria e configura elemento script
    const script = document.createElement('script');
    script.src = src;
    if (integrity) script.integrity = integrity;
    if (crossOriginAttr) script.crossOrigin = crossOriginAttr;
    script.defer = true;

    // Configura tratamento de erro e fallback
    script.onerror = (event) => {
        console.warn(`SECURITY MODULE: Falha ao carregar ${src}`, event);
        if (validFallbackSrc && !loadedScripts.has(validFallbackSrc)) {
             console.warn(`SECURITY MODULE: Tentando fallback ${validFallbackSrc}`);
             loadExternalScript(validFallbackSrc, {}); // Recursivo com options limpo
        } else if (validFallbackSrc) {
             console.warn(`SECURITY MODULE: Fallback ${validFallbackSrc} já tentado ou inválido.`);
        }
    };

    // Adiciona script ao DOM
    if (document.head) {
        document.head.appendChild(script);
    } else {
        console.error("SECURITY MODULE: Falha ao carregar script - document.head não encontrado.");
    }
}

/**
 * Valida se a entrada tem comprimento mínimo após trim.
 * Útil para validações básicas de formulários.
 * 
 * @param {*} input - Entrada a validar
 * @param {number} [minLength=1] - Comprimento mínimo exigido
 * @returns {boolean} - true se válido
 */
function validateMinLength(input, minLength = 1) {
    return String(input ?? '').trim().length >= minLength;
}

/**
 * Obtém elemento do DOM com tratamento de erros.
 * Wrapper seguro para querySelector.
 * 
 * @param {string} selector - Seletor CSS
 * @returns {HTMLElement | null} - Elemento encontrado ou null
 */
function getElement(selector) {
    try {
        const element = document.querySelector(selector);
        if (!element) {
            console.warn(`SECURITY MODULE: Elemento não encontrado: ${selector}`);
        }
        return element;
    } catch (error) {
        console.error(`SECURITY MODULE: Erro no seletor '${selector}':`, error);
        return null;
    }
}

/**
 * Define conteúdo de elemento de forma segura contra XSS.
 * Usa abordagem específica para elementos SVG vs HTML.
 * 
 * @param {Element | null} element - Elemento a modificar
 * @param {*} content - Conteúdo a inserir (será escapado)
 */
export function safeInnerHTML(element, content) {
    // Validação defensiva do elemento
    if (element?.nodeType !== 1) {
        console.error('SECURITY MODULE: safeInnerHTML chamado com elemento inválido.');
        return;
    }
    
    // Tratamento especial para SVG (mais seguro usar textContent)
    if (element.namespaceURI === 'http://www.w3.org/2000/svg') {
        element.textContent = String(content ?? '');
    } else {
        // Para elementos HTML, escapa o conteúdo antes de definir innerHTML
        element.innerHTML = escapeHtml(content);
    }
}

/**
 * Inicializa política Trusted Types para navegadores modernos.
 * Protege automaticamente sinks DOM perigosos.
 * 
 * @private
 */
function initTrustedTypes() {
   if (window.trustedTypes && window.trustedTypes.createPolicy) {
       try {
           // Cria política 'default' para sanitização automática
           window.trustedTypes.createPolicy('default', {
               // Escapa HTML antes de inserção no DOM
               createHTML: (string) => escapeHtml(string),
               
               // Permite scripts (CSP controla execução)
               createScript: (string) => string,
               
               // Valida URLs de script antes de carregar
               createScriptURL: (string) => {
                   if (isAllowedProtocol(string)) return string;
                   const errorMsg = `SECURITY MODULE: URL de script bloqueada por Trusted Types: ${string}`;
                   console.error(errorMsg);
                   throw new TypeError(errorMsg);
               }
           });
           // Log desativado para manter silêncio (KISS)
           // console.info('SECURITY MODULE: Trusted Types política padrão inicializada.');
       } catch (e) {
           // Ignora erro se política já existir (comum em carregamentos duplicados)
           if (e.message.includes('Policy "default" already exists')) {
               // Log informativo opcional desativado (KISS)
               // console.info('SECURITY MODULE: Política Trusted Types "default" já existe.');
           } else {
               console.error('SECURITY MODULE: Falha ao inicializar Trusted Types:', e);
           }
       }
   }
}

// --- Inicialização Imediata com Proteção contra Duplicação ---
if (!window.__securityModuleLoaded) {
    initTrustedTypes(); // Inicializa Trusted Types antes da CSP
    applyBasicCSP();    // Aplica CSP via meta tag
    window.__securityModuleLoaded = true;
}

// --- Exportações Públicas ---
export {
    escapeHtml,         // Escapa HTML para prevenção de XSS
    cleanNumber,        // Limpa e valida entrada numérica
    cleanText,          // Limpa e limita texto
    setSecureCookie,    // Define cookies seguros
    loadExternalScript, // Carrega scripts com controles de segurança
    validateMinLength,  // Valida comprimento mínimo
    getElement,         // Obtém elemento DOM com segurança
    safeInnerHTML,      // Define HTML de forma segura
};