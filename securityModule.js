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
(function(window) {
  // --- Bloco de Guarda: Previne re-execução ---
  if (window.__securityEssentialsLoaded) {
      console.warn("SECURITY ESSENTIALS: Módulo já carregado. Ignorando re-execução.");
      return;
  }
  // --- Fim Bloco de Guarda ---

  // Objeto para expor a API pública
  const SecurityEssentials = {};

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
 * Regex para caracteres de controle ASCII C0 (exceto HT, LF, CR) e C1.
 * Usado opcionalmente em cleanText.
 * @private
 */
const CONTROL_CHARS_REGEX = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

/**
 * Lista de protocolos de URL considerados seguros para uso geral.
 * Usado por sanitizeURL e na política Trusted Types.
 * @private
 * @type {string[]}
 */
const ALLOWED_PROTOCOLS = [
    'https:',
    'http:', // Permitido, mas HTTPS é preferível
    'mailto:',
    'ftp:' // Inclua apenas se necessário
];

/**
 * Escapa caracteres HTML especiais e separadores de linha/parágrafo Unicode.
 * Função fundamental para prevenção de XSS em conteúdo dinâmico.
 *
 * @param {*} input - A entrada a ser escapada (qualquer tipo)
 * @returns {string} - String segura para uso em contextos HTML
 */
function escapeHtml(input) {
    const str = String(input ?? '');
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
    // Validação final - verifica se é número e finito
    return !isNaN(num) && isFinite(num) ? num : null;
}

/**
 * Limpa texto: remove espaços/etc. das pontas, opcionalmente remove
 * caracteres de controle, e limita o comprimento máximo.
 *
 * @param {*} input - O valor a ser limpo.
 * @param {number} [maxLength=1000] - O comprimento máximo desejado.
 * @param {boolean} [removeControlChars=false] - Se true, remove caracteres de controle C0/C1 (exceto HT, LF, CR).
 * @returns {string} - O texto limpo/sanitizado e limitado.
 */
export function cleanText(input, maxLength = 1000, removeControlChars = false) {
    let str = String(input ?? '');
    if (removeControlChars) {
        str = str.replace(CONTROL_CHARS_REGEX, '');
    }
    str = str.trim();
    return str.substring(0, maxLength);
}

// ===== FUNÇÃO ALTERNATIVA MAIS SIMPLES (NÃO USA API URL) =====

/**
 * Verifica de forma extremamente simples se uma URL *começa* com um protocolo
 * conhecido por ser perigoso para execução de script ('javascript:', 'data:', 'vbscript:').
 * Retorna true se for potencialmente perigoso, false caso contrário.
 * NÃO valida o formato da URL nem outros protocolos. Confia na validação HTML
 * e na CSP para outras proteções.
 *
 * @param {string | null | undefined} urlInput - A URL a ser verificada.
 * @returns {boolean} - true se começar com 'javascript:', 'data:' ou 'vbscript:', false caso contrário.
 */
export function isPotentiallyMaliciousURL(urlInput) {
    const urlString = String(urlInput ?? '').trim();

    // Verificação KISS: A string começa com 'javascript:', 'data:' ou 'vbscript:' (ignorando case)?
    return /^\s*(javascript|data|vbscript):/i.test(urlString);
}

// ==========================================================

// ===== AJUSTAR getSafeURL ou REMOVER =====
// Você pode manter getSafeURL como está ou simplificá-la para usar isPotentiallyMaliciousURL:

/**
 * Retorna a URL original se ela NÃO começar com um protocolo perigoso,
 * ou uma string vazia caso contrário. Versão KISS que não valida formato nem
 * resolve caminhos relativos.
 *
 * @param {string | null | undefined} urlInput - A URL a ser verificada.
 * @returns {string} - A URL original (trim) ou ''.
 */
export function getSafeURL(urlInput) {
    const urlString = String(urlInput ?? '').trim();
    const SAFE_FALLBACK = '';

    if (isPotentiallyMaliciousURL(urlString)) {
         console.warn(`SECURITY MODULE: getSafeURL_KISS - Protocolo potencialmente perigoso detectado: ${urlString.substring(0, 50)}...`);
        return SAFE_FALLBACK;
    }

    // Se não for detectado como malicioso, retorna a string original (após trim)
    // Confia no navegador/CSP/validação server-side para o resto.
    return urlString;
}

// ===============================================
/**
 * Gera um nonce criptograficamente seguro (32 bytes / 256 bits).
 * Usado para CSP e outras necessidades de tokens seguros.
 *
 * @private
 * @returns {string} - Nonce em formato hexadecimal ou 'CRYPTO_ERROR' em caso de falha
 */
function generateNonce() {
    const buffer = new Uint8Array(32);
    try {
        window.crypto.getRandomValues(buffer);
        return Array.from(buffer, byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (e) {
        console.error("SECURITY MODULE: Falha crítica - crypto.getRandomValues indisponível/falhou.", e);
        return 'CRYPTO_ERROR';
    }
}

/**
 * Aplica Content Security Policy (CSP) via meta tag automaticamente.
 * Configurada para bloquear a maioria dos vetores XSS comuns.
 *
 * @private
 */
function applyBasicCSP() {
    if (document.querySelector('meta[http-equiv="Content-Security-Policy"]')) return;
    const scriptNonce = generateNonce();
    const styleNonce = generateNonce();
    if (scriptNonce === 'CRYPTO_ERROR' || styleNonce === 'CRYPTO_ERROR') return;

    const cspPolicy = [
        "default-src 'none'",
        "script-src 'self' 'strict-dynamic' 'nonce-" + scriptNonce + "'",
        "style-src 'self' 'nonce-" + styleNonce + "' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' https:",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    ].join('; ');
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
 * Nota: O atributo HttpOnly deve ser aplicado pelo servidor para
 * proteção completa contra XSS.
 *
 * @param {string} name - Nome do cookie (não pode ser vazio)
 * @param {*} value - Valor a ser armazenado (convertido para string)
 * @param {number} [days=7] - Duração em dias (0 para sessão)
 * @param {string} [path='/'] - Path do cookie (deve começar com '/')
 */
export function setSecureCookie(name, value, days = 7, path = '/') {
    if (typeof name !== 'string' || name.trim() === '') {
        console.error('SECURITY MODULE: Nome do cookie inválido.');
        return;
    }
    if (value === undefined || value === null) {
       console.error('SECURITY MODULE: Valor do cookie inválido (undefined/null).');
       return;
    }
    if (typeof path !== 'string' || !path.startsWith('/')) {
       console.warn(`SECURITY MODULE: Path do cookie inválido ('${path}'). Usando '/'.`);
       path = '/';
    }
    let expiresAttribute = '';
    if (days && typeof days === 'number' && days > 0) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        expiresAttribute = `; expires=${date.toUTCString()}`;
    }
    const secureAttribute = window.location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = `${name}=${encodeURIComponent(String(value))}${expiresAttribute}; path=${path}${secureAttribute}; SameSite=Strict`;
    /* Nota: Configure HttpOnly no servidor para máxima proteção! */
}

/**
 * Rastreia scripts já carregados para prevenir duplicação.
 * @private @type {Set<string>}
 */
const loadedScripts = new Set();

/**
 * Verifica se o protocolo da URL é permitido para carregamento seguro.
 * @private
 * @param {string} src - URL a verificar
 * @returns {boolean} - true se protocolo for seguro (https ou relativo)
 */
function isAllowedProtocol(src) {
    // Trim para evitar falhas por espaços extras
    const trimmedSrc = String(src ?? '').trim();
    return trimmedSrc.startsWith('https://') || trimmedSrc.startsWith('/') || trimmedSrc.startsWith('./') || trimmedSrc.startsWith('../');
}

/**
 * Carrega script externo com verificações de segurança:
 * - Validação de protocolo (apenas HTTPS e relativos)
 * - Suporte a Subresource Integrity (SRI)
 * - Controle CORS
 * - Fallback automático
 *
 * @param {string} src - URL do script principal
 * @param {object} [options={}] - Opções de carregamento
 * @param {string|null} [options.integrity=null] - Hash SRI (sha256/384/512)
 * @param {string|null} [options.crossorigin='anonymous'|'use-credentials'] - Modo CORS (auto 'anonymous' se integrity)
 * @param {string|null} [options.fallbackSrc=null] - URL alternativa se principal falhar
 */
export function loadExternalScript(src, options = {}) {
    const { integrity = null, crossorigin = null, fallbackSrc = null } = options;

    const trimmedSrc = String(src ?? '').trim(); // Usa versão trim para checagens
    if (!trimmedSrc) {
         console.error('SECURITY MODULE: URL do script inválida (vazia).');
        return;
    }
    if (!isAllowedProtocol(trimmedSrc)) { // Usa trimmedSrc
        console.error(`SECURITY MODULE: Protocolo não permitido para script src: ${trimmedSrc}.`);
        return;
    }

    let validFallbackSrc = null;
    const trimmedFallback = String(fallbackSrc ?? '').trim();
    if (trimmedFallback) {
        if (isAllowedProtocol(trimmedFallback)) { // Usa trimmedFallback
            validFallbackSrc = trimmedFallback;
        } else {
             console.error(`SECURITY MODULE: Protocolo não permitido para fallback: ${trimmedFallback}.`);
             // Não define validFallbackSrc, efetivamente o descarta
        }
    }

    if (loadedScripts.has(trimmedSrc)) return; // Usa trimmedSrc
    loadedScripts.add(trimmedSrc); // Usa trimmedSrc

    const crossOriginAttr = integrity ? (crossorigin || 'anonymous') : crossorigin;

    if (!integrity && trimmedSrc.startsWith('https://')) { // Usa trimmedSrc
        console.warn(`SECURITY MODULE: Carregando script externo sem SRI: ${trimmedSrc}`);
    }

    const script = document.createElement('script');
    script.src = trimmedSrc; // Usa trimmedSrc
    if (integrity) script.integrity = integrity;
    if (crossOriginAttr) script.crossOrigin = crossOriginAttr;
    script.defer = true;

    script.onerror = (event) => {
        console.warn(`SECURITY MODULE: Falha ao carregar ${trimmedSrc}`, event); // Usa trimmedSrc
        if (validFallbackSrc && !loadedScripts.has(validFallbackSrc)) {
             console.warn(`SECURITY MODULE: Tentando fallback ${validFallbackSrc}`);
             loadExternalScript(validFallbackSrc, {});
        } else if (validFallbackSrc) {
             console.warn(`SECURITY MODULE: Fallback ${validFallbackSrc} já tentado ou inválido.`);
        }
    };

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
    if (element?.nodeType !== 1) {
        console.error('SECURITY MODULE: safeInnerHTML chamado com elemento inválido.');
        return;
    }
    if (element.namespaceURI === 'http://www.w3.org/2000/svg') {
        element.textContent = String(content ?? '');
    } else {
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
           window.trustedTypes.createPolicy('default', {
               createHTML: (string) => escapeHtml(string),
               createScript: (string) => string,
               createScriptURL: (string) => {
                   const trimmedString = String(string ?? '').trim(); // Trim antes de validar
                   if (isAllowedProtocol(trimmedString)) return trimmedString; // Usa e retorna trimmed
                   const errorMsg = `SECURITY MODULE: URL de script bloqueada por Trusted Types: ${trimmedString}`;
                   console.error(errorMsg);
                   throw new TypeError(errorMsg);
               }
           });
           // console.info('SECURITY MODULE: Trusted Types política padrão inicializada.');
       } catch (e) {
           if (e.message.includes('Policy "default" already exists')) {
               // console.info('SECURITY MODULE: Política Trusted Types "default" já existe.');
           } else {
               console.error('SECURITY MODULE: Falha ao inicializar Trusted Types:', e);
           }
       }
   }
}

// --- Inicialização Imediata com Proteção contra Duplicação ---
if (!window.__securityModuleLoaded) {
    initTrustedTypes();
    applyBasicCSP();
    window.__securityModuleLoaded = true;
}

// --- Exportações Públicas ---
export {
    escapeHtml,
    cleanNumber,
    cleanText,
    getSafeURL, // Incluída
    setSecureCookie,
    loadExternalScript,
    validateMinLength,
    getElement,
    safeInnerHTML,
};