/**
 * =============================================================================
 * securityUtils.mjs - Utilitários Essenciais de Segurança Client-Side (ESM)
 * =============================================================================
 * Fornece funções mínimas e essenciais para tarefas comuns de segurança
 * no front-end, como um módulo ES6. Foco em primitivas KISS e clareza.
 * Assume ambiente de navegador padrão (DOM, window.crypto, window.location).
 *
 * Funções Exportadas:
 * - escapeHtml: Previne XSS em conteúdo HTML via escaping.
 * - cleanNumber: Valida e retorna números finitos (remove vírgulas).
 * - cleanText: Limpa (trim) e limita comprimento de strings.
 * - sanitizeURL: Valida URLs (protocolos seguros/relativos).
 * - generateNonce: Gera nonce seguro para CSP (requer window.crypto).
 * - setSecureCookie: Define cookies com flags de segurança (requer document).
 * - loadExternalScript: Carrega scripts externos com segurança (requer document).
 *
 * Uso: import { functionName } from './securityUtils.mjs';
 * =============================================================================
 */

// --- Verificação de Ambiente (Defesa Mínima) ---
if (typeof window === 'undefined' || typeof document === 'undefined') {
    console.warn('SecurityUtils: Módulo carregado fora de um ambiente de navegador padrão. Algumas funções podem não operar corretamente.');
}

// --- Constantes Internas (Privadas ao Módulo) ---
const HTML_ESCAPE_MAP = Object.freeze({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '/': '&#x2F;',
    '`': '&#96;'
});
const HTML_ESCAPE_REGEX = /[&<>"'`/]/g;

// Protocolos permitidos por sanitizeURL. Lista mínima e segura.
const ALLOWED_PROTOCOLS = Object.freeze(['https:', 'http:', 'mailto:']);

// Estado interno para loadExternalScript (evita recarga).
const loadedScripts = new Set();

// --- Funções Públicas Exportadas --

export function escapeHtml(input) {
    const str = String(input ?? '');
    return str.replace(HTML_ESCAPE_REGEX, (char) => HTML_ESCAPE_MAP[char]);
}

export function cleanNumber(input) {
    const strInput = String(input ?? '').replace(/,/g, '');
    if (!strInput) return null;
    const num = Number(strInput);
    return Number.isFinite(num) ? num : null;
}

export function cleanText(input, maxLength = 1000) {
    const str = String(input ?? '').trim();
    const effectiveMaxLength = Math.max(0, Math.floor(maxLength));
    return str.substring(0, effectiveMaxLength);
}

/**
 * Valida URL: Permite apenas protocolos seguros (ver ALLOWED_PROTOCOLS)
 * ou URLs relativas. Retorna a URL trimada se válida, senão null.
 * Advertência: 'mailto:' pode ser usado em phishing. Considere remover se não necessário.
 * @param {*} inputUrl A URL a ser validada.
 * @returns {string | null} A URL validada ou null.
 */
export function sanitizeURL(inputUrl) {
    const urlString = String(inputUrl ?? '').trim();
    if (!urlString) return null;
    if (
        urlString.startsWith('/') ||
        urlString.startsWith('./') ||
        urlString.startsWith('../') ||
        !urlString.includes(':')
    ) {
         if (!urlString.includes(':') && /[<>"`']/.test(urlString)) { // Defesa extra KISS
             console.warn(`SecurityUtils: Caracteres potencialmente perigosos em URL relativa/sem esquema: ${urlString}`);
             return null;
         }
        return urlString;
    }
    try {
        const parsedUrl = new URL(urlString);
        if (ALLOWED_PROTOCOLS.includes(parsedUrl.protocol.toLowerCase())) {
            return urlString; // Retorna original validada, não normalizada
        }
        return null;
    } catch (e) {
        return null;
    }
}

export function generateNonce() {
    if (!window?.crypto?.getRandomValues) {
        console.error("SecurityUtils: window.crypto.getRandomValues não disponível.");
        return null;
    }
    const buffer = new Uint8Array(32);
    try {
        window.crypto.getRandomValues(buffer);
        // Usar map diretamente no Array.from ou spread+map é ok.
        return Array.from(buffer, (byte) => byte.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        console.error("SecurityUtils: Falha ao gerar nonce via crypto.", error);
        return null;
    }
}

export function setSecureCookie(name, value, options = {}) {
    // Verifica se cookies estão habilitados
    if (typeof navigator !== 'undefined' && !navigator.cookieEnabled) {
        console.warn("SecurityUtils: Cookies estão desativados no navegador.");
        return;
    }
    const encodedName = encodeURIComponent(String(name ?? '').trim());
    if (!encodedName) {
        console.error("SecurityUtils: Nome de cookie inválido fornecido.");
        return;
    }
    const encodedValue = encodeURIComponent(String(value ?? ''));
    const { days, path = '/' } = options;
    let cookieString = `${encodedName}=${encodedValue}`;
    const safePath = (typeof path === 'string' && path.startsWith('/')) ? path : '/';
    cookieString += `; path=${safePath}`;
    if (typeof days === 'number' && days > 0) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        cookieString += `; expires=${date.toUTCString()}`;
    }
    if (window?.location?.protocol === 'https:') {
        cookieString += '; Secure';
    }
    cookieString += '; SameSite=Strict';
    try {
        if (typeof document?.cookie !== 'undefined') {
            document.cookie = cookieString;
        } else {
            console.warn("SecurityUtils: 'document' não disponível para setSecureCookie.");
        }
    } catch (error) {
        console.error("SecurityUtils: Falha ao tentar definir cookie.", error);
    }
}

/**
 * Carrega script externo dinamicamente com segurança utilizando Promises.
 * Valida URL (HTTPS/relativo), evita recarga (considerando src, integrity, crossorigin),
 * suporta SRI, CORS e adição de nonce externo.
 * @param {string} src URL do script (HTTPS ou relativo).
 * @param {object} [options] Opções: { integrity?: string, crossorigin?: 'anonymous'|'use-credentials', nonce?: string }.
 * @returns {Promise<void>} Promise resolvida quando o script é carregado ou rejeitada em caso de erro.
 */
export function loadExternalScript(src, options = {}) {
    return new Promise((resolve, reject) => {
        const { integrity, crossorigin, nonce } = options;
        const trimmedSrc = String(src ?? '').trim();

        // 1. Validar URL
        const isSrcAllowed =
            trimmedSrc &&
            (trimmedSrc.startsWith('https://') ||
             trimmedSrc.startsWith('/') ||
             trimmedSrc.startsWith('./') ||
             trimmedSrc.startsWith('../') ||
             !trimmedSrc.includes(':'));
        if (!isSrcAllowed || (!trimmedSrc.includes(':') && /[<>"`']/.test(trimmedSrc)) ) {
             const errorMsg = `SecurityUtils: URL de script inválida, não permitida ou com caracteres perigosos: ${trimmedSrc}`;
             console.error(errorMsg);
             reject(new Error(errorMsg));
             return;
        }


        // 2. Evitar Recarga usando Chave Composta
        const scriptKey = `${trimmedSrc}|${integrity || ''}|${crossorigin || ''}`;
        if (loadedScripts.has(scriptKey)) {
            resolve();
            return;
        }
        loadedScripts.add(scriptKey);

        // 3. Verificar DOM
        if (typeof document?.createElement !== 'function') {
            const errorMsg = "SecurityUtils: 'document' não disponível para loadExternalScript.";
            console.error(errorMsg);
            loadedScripts.delete(scriptKey);
            reject(new Error(errorMsg));
            return;
        }

        // 4. Criar e Configurar Script
        const script = document.createElement('script');
        script.src = trimmedSrc;
        script.defer = true;
        if (nonce) script.nonce = nonce;
        if (integrity) {
            script.integrity = integrity;
            script.crossOrigin = crossorigin || 'anonymous';
        } else if (crossorigin) {
            script.crossOrigin = crossorigin;
        }

        // 5. Handlers da Promise
        script.onload = () => resolve();
        script.onerror = (event) => {
            const errorMsg = `Falha ao carregar script ${trimmedSrc}`;
            console.error(`SecurityUtils: ${errorMsg}`, event?.type);
            loadedScripts.delete(scriptKey);
             try { // Tenta remover o script falho do DOM
                 script.remove();
             } catch(removeError) {
                 console.warn("SecurityUtils: Não foi possível remover o script falho do DOM.", removeError);
             }
            reject(new Error(errorMsg));
        };

        // 6. Adicionar ao DOM
        (document.head || document.documentElement).appendChild(script);
    });
}