// securityModule.js

const HTML_ESCAPE = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#x27;',
    '`': '&#x60;'
};

/**
 * Sanitiza entradas com base no tipo esperado.
 * @param {*} input Entrada do usuário.
 * @param {string} type Tipo esperado: 'default', 'letters', 'number', 'email', 'date'.
 * @returns {string|number|null} Valor sanitizado.
 */
function sanitizeInput(input, type = 'default') {
    if (input === undefined || input === null) return type === 'number' ? null : '';

    const str = String(input).trim().substring(0, 1000); // Limite de 1000 caracteres

    switch (type) {
        case 'number':
            return /^[+-]?\d*\.?\d+$/.test(str) ? parseFloat(str) : null;
        case 'letters':
            return str.replace(/[^a-zA-ZÀ-ÿ\s]/g, '');
        case 'email':
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(str) ? str : '';
        case 'date':
            return /^\d{4}-\d{2}-\d{2}$/.test(str) ? str : '';
        default:
            return str;
    }
}

/**
 * Função genérica de escapagem configurável por contexto.
 * @param {*} input Entrada a ser escapada.
 * @param {string} context Contexto: 'html', 'css', 'js'.
 */
function escape(input, context) {
    const str = String(input);
    switch (context) {
        case 'html':
            return str.replace(/[&<>"'`]/g, c => HTML_ESCAPE[c]);
        case 'css':
            return str.replace(/[^a-zA-Z0-9_#.,:-]/g, '');
        case 'js':
            return str
                .replace(/\\/g, '\\\\')
                .replace(/'/g, '\\\'')
                .replace(/"/g, '\\"')
                .replace(/</g, '\\u003C')
                .replace(/>/g, '\\u003E')
                .replace(/&/g, '\\u0026');
        default:
            throw new Error('Contexto de escapagem inválido');
    }
}


/**
 * Sanitiza URLs, retornando URL absoluta padrão em falhas.
 */
function sanitizeURL(input) {
    const str = String(input).trim();
    if (/^(javascript|data|vbscript):/i.test(str)) return window.location.origin;

    try {
        const url = new URL(str, window.location.origin);
        return ['http:', 'https:', 'ftp:'].includes(url.protocol) ? url.href : window.location.origin;
    } catch {
        return /^\/[\w-]/.test(str) || str.startsWith('#') ? str : window.location.origin;
    }
}

/**
 * Gera um nonce seguro para CSP.
 */
function generateNonce() {
    return Array.from(window.crypto.getRandomValues(new Uint8Array(16)))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Aplica a Política de Segurança de Conteúdo (CSP) sem 'unsafe-inline'.
 */
function applyCSP() {
    const scriptNonce = generateNonce();
    const styleNonce = generateNonce();

    const cspPolicy = `
        default-src 'none';
        script-src 'self' 'strict-dynamic' 'nonce-${scriptNonce}' https:;
        style-src 'self' 'nonce-${styleNonce}' https://fonts.googleapis.com;
        font-src 'self' https://fonts.gstatic.com;
        img-src 'self' data:;
        connect-src 'self';
        form-action 'self';
        base-uri 'none';
        frame-ancestors 'none';
        report-uri /csp-report;
    `.replace(/\s+/g, ' ');

    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = cspPolicy;
    document.head.prepend(meta);

    return { scriptNonce, styleNonce };
}

/**
 * Configura cookies seguros com path configurável.
 */
function setSecureCookie(name, value, days = 7, path = '/app') {
    const expires = new Date(Date.now() + days * 864e5).toUTCString();
    document.cookie = `${name}=${encodeURIComponent(value)}; 
                       expires=${expires}; 
                       path=${path}; 
                       Secure; 
                       HttpOnly; 
                       SameSite=Strict`;
}

/**
 * Carrega scripts externos com cache, SRI, e fallback.
 */
const loadedScripts = new Set();
function loadExternalScript(src, integrity, crossorigin = 'anonymous', fallbackSrc) {
    if (loadedScripts.has(src)) return;
    loadedScripts.add(src);

    const script = document.createElement('script');
    script.src = src;
    script.integrity = integrity;
    script.crossOrigin = crossorigin;
    script.defer = true;
    script.onerror = () => {
        console.warn(`Falha ao carregar ${src}, usando fallback.`);
        const fallbackScript = document.createElement('script');
        fallbackScript.src = fallbackSrc;
        document.head.appendChild(fallbackScript);
    };
    document.head.appendChild(script);
}

/**
 * Valida entrada com comprimento mínimo.
 */
function validateInput(input, minLength = 0) {
    return String(input).length >= minLength;
}

/**
 * Função auxiliar para obter elementos do DOM.
 */
function getElement(selector) {
    const element = document.querySelector(selector);
    if (!element) console.warn(`Elemento ${selector} não encontrado.`);
    return element;
}

/**
 * Hash de entrada usando Web Crypto API.
 */
async function hashInput(input) {
    const encoder = new TextEncoder();
    const data = encoder.encode(input);
    const hash = await window.crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Integração segura no DOM
document.addEventListener('DOMContentLoaded', async () => {
    const { scriptNonce, styleNonce } = applyCSP();

    loadExternalScript(
        'https://cdn.example.com/lib.js',
        'sha384-abc123XYZ...',
        'anonymous',
        '/local-lib.js'
    );

    const form = getElement('#securityTestForm');
    const resultsDiv = getElement('#results');
    if (!form || !resultsDiv) return;

    const textInput = getElement('input[name="textInput"]');
    const numberInput = getElement('input[name="numberInput"]');
    const letterInput = getElement('input[name="letterInput"]');
    const urlInput = getElement('input[name="urlInput"]');
    if (!textInput || !numberInput || !letterInput || !urlInput) return;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
            if (!validateInput(textInput.value, 3)) {
                resultsDiv.innerHTML = '<p class="error">Texto muito curto.</p>';
                return;
            }

            const textOutput = escape(sanitizeInput(textInput.value), 'html');
            const numberOutput = sanitizeInput(numberInput.value, 'number');
            const letterOutput = sanitizeInput(letterInput.value, 'letters');
            const urlOutput = sanitizeURL(urlInput.value);

            const hashedText = await hashInput(textInput.value);
            console.log(`Hash do texto: ${hashedText}`);

            resultsDiv.innerHTML = `
                <p><strong>Texto Sanitizado:</strong> ${textOutput}</p>
                <p><strong>Número Sanitizado:</strong> ${numberOutput}</p>
                <p><strong>Apenas Letras:</strong> ${letterOutput}</p>
                <p><strong>URL Sanitizada:</strong> ${urlOutput}</p>
            `;
        } catch (error) {
            console.error('Erro ao processar o formulário:', error);
            resultsDiv.innerHTML = '<p class="error">Entrada inválida, tente novamente.</p>';
        }
    });

    window.onerror = (msg) => console.warn(`Erro de segurança: ${msg}`);
});