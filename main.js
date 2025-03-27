import { 
    sanitizeInput, 
    escapeHTML, 
    escapeJS, 
    escapeCSS, 
    sanitizeURL, 
    applyCSP 
} from './xssProtecao.js';

/**
 * Função auxiliar para exibir alterações (caso o valor sanitizado seja diferente do original).
 * Usa escapeHTML para evitar XSS na exibição.
 */
function getChanges(original, sanitized) {
    return original !== sanitized 
        ? `<span class="changed">(Alterado de: ${escapeHTML(original)})</span>` 
        : '';
}

/**
 * Extrai os casos de teste da tabela com id "testList".
 * Espera que a tabela possua 4 colunas: Tipo, Valor, Esperado e Descrição.
 */
function getTestData() {
    const data = [];
    // Seleciona somente as linhas dentro do tbody, se existir
    const rows = document.querySelectorAll('#testList tbody tr') || document.querySelectorAll('#testList tr');
    for (let i = 1; i < rows.length; i++) {
        const cells = rows[i].querySelectorAll('td');
        if (cells.length === 4) {
            data.push({
                type: cells[0].textContent.trim(),
                value: cells[1].textContent.trim(),
                expected: cells[2].textContent.trim(),
                description: cells[3].textContent.trim()
            });
        }
    }
    return data;
}

/**
 * Compara o resultado sanitizado com o esperado, com base no tipo e nos dados de teste.
 * Retorna uma mensagem informativa com ícones e o valor obtido.
 */
function compareWithExpected(type, result, testData) {
    // Procura o caso de teste que tenha o mesmo tipo e valor original
    const test = testData.find(t => t.type === type && t.value === result.original);
    if (test) {
        const comparison = result.sanitized === test.expected 
            ? '✅ Sucesso' 
            : `❌ Falha - Esperado: ${test.expected}`;
        return `${comparison} (Obtido: ${escapeHTML(result.sanitized)}) ${getChanges(result.original, result.sanitized)}`;
    }
    return 'ℹ️ Nenhum teste correspondente encontrado';
}

document.addEventListener('DOMContentLoaded', () => {
    // Aplica a política de segurança de conteúdo (CSP) imediatamente
    applyCSP();

    // Seleciona os elementos do formulário e área de resultados
    const form = document.querySelector('#securityTestForm');
    const resultsDiv = document.querySelector('#results');
    const textInput = form.querySelector('#textInput');
    const numberInput = form.querySelector('#numberInput');
    const alphaInput = form.querySelector('#alphaInput');
    const urlInput = form.querySelector('#urlInput');
    const randomTestButton = document.querySelector('#randomTestButton');
    
    // Obtém os casos de teste da tabela
    let testData = getTestData();

    form.addEventListener('submit', (event) => {
        event.preventDefault();
        try {
            // Captura os valores originais dos inputs
            const textVal = textInput.value;
            const numberVal = numberInput.value;
            const alphaVal = alphaInput.value;
            const urlVal = urlInput.value;
            
            // Sanitiza os valores usando as funções do módulo de segurança
            const textResult = { original: textVal, sanitized: escapeHTML(sanitizeInput(textVal, 'string')) };
            const numberResult = { original: numberVal, sanitized: String(sanitizeInput(numberVal, 'number')) };
            const alphaResult = { original: alphaVal, sanitized: sanitizeInput(alphaVal, 'alphanumeric') };
            const urlResult = { original: urlVal, sanitized: sanitizeURL(urlVal) };

            // Compara os resultados com os casos de teste (usando a tabela)
            const textComparison = compareWithExpected('Texto', textResult, testData);
            const numberComparison = compareWithExpected('Número', numberResult, testData);
            const alphaComparison = compareWithExpected('Alfanumérico', alphaResult, testData);
            const urlComparison = compareWithExpected('URL', urlResult, testData);

            // Exibe os resultados na área de resultados
            resultsDiv.innerHTML = `
                <h3>Resultado</h3>
                <p><strong>Texto:</strong> ${textComparison}</p>
                <p><strong>Número:</strong> ${numberComparison}</p>
                <p><strong>Alfanumérico:</strong> ${alphaComparison}</p>
                <p><strong>URL:</strong> ${urlComparison}</p>
            `;
            resultsDiv.classList.add('show');
        } catch (e) {
            console.error('Erro ao processar os dados:', e);
            resultsDiv.innerHTML = `<p class="error">Erro: ${e.message}</p>`;
            resultsDiv.classList.remove('show');
        }
    });

    // Evento do botão "Teste Aleatório": seleciona aleatoriamente um caso de teste da tabela
    randomTestButton.addEventListener('click', () => {
        if (!testData || testData.length === 0) {
            resultsDiv.innerHTML = `<p class="error">Nenhum teste carregado.</p>`;
            return;
        }
        const randomIndex = Math.floor(Math.random() * testData.length);
        const test = testData[randomIndex];
        // Preenche os inputs conforme o tipo do teste
        textInput.value = test.type === 'Texto' ? test.value : '';
        numberInput.value = test.type === 'Número' ? test.value : '';
        alphaInput.value = test.type === 'Alfanumérico' ? test.value : '';
        urlInput.value = test.type === 'URL' ? test.value : '';
        // Dispara o submit para processar o teste
        form.requestSubmit();
    });
});