# securityWebTest

## Introdução

O securityWebTest é um projeto dedicado a demonstrar e testar as funcionalidades do `securityUtils.mjs`, um módulo JavaScript focado em sanitização de entradas e utilidades de segurança do lado do cliente. O objetivo principal é fornecer ferramentas para limpar e validar dados de entrada, ajudando a prevenir vulnerabilidades comuns como Cross-Site Scripting (XSS). O projeto inclui uma página de teste interativa (`index.html`) que utiliza um arquivo de casos de teste (`testList.html`) para verificar o comportamento das funções de sanitização.

## Módulo de Segurança (`securityUtils.mjs`)

O `securityUtils.mjs` é o coração deste projeto, oferecendo um conjunto de funções projetadas para sanitizar e limpar diversos tipos de dados. Essas utilidades são essenciais para garantir que apenas dados seguros sejam processados ou exibidos em aplicações web.

### Funções Disponíveis:

*   **`escapeHtml(text)`**: Escapa caracteres HTML especiais em uma string (por exemplo, `<`, `>`, `&`, `"`, `'`) para prevenir XSS. Substitui esses caracteres por suas respectivas entidades HTML.
*   **`cleanNumber(value, defaultValue = 0)`**: Tenta converter um valor para um número inteiro. Se a conversão falhar, retorna um valor padrão (0, se não especificado). Remove quaisquer caracteres não numéricos.
*   **`cleanText(text, maxLength = 255, allowedChars = null)`**: Limpa uma string de texto. Remove espaços em branco extras, trunca o texto para um `maxLength` especificado, e opcionalmente remove quaisquer caracteres que não estejam na lista `allowedChars`.
*   **`sanitizeURL(url)`**: Tenta sanitizar uma URL, removendo caracteres potencialmente perigosos ou malformados. O objetivo é permitir apenas URLs que sigam um formato seguro e esperado. *(Nota: A implementação atual desta função pode precisar de refinamento para cobrir todos os vetores de ataque de URL).*

### Como Usar o Módulo:

Para utilizar o `securityUtils.mjs` em seus projetos JavaScript, importe-o como um módulo ES:

```javascript
import * as securityUtils from './securityUtils.mjs';

const htmlPerigoso = "<script>alert('XSS');</script>";
const htmlSeguro = securityUtils.escapeHtml(htmlPerigoso);
console.log(htmlSeguro); // Saída: &lt;script&gt;alert('XSS');&lt;/script&gt;

const numeroSujo = "123.45abc";
const numeroLimpo = securityUtils.cleanNumber(numeroSujo);
console.log(numeroLimpo); // Saída: 123

const textoLongo = "  Este é um texto    muito longo com espaços extras.  ";
const textoLimpo = securityUtils.cleanText(textoLongo, 30);
console.log(textoLimpo); // Saída: Este é um texto muito longo c
```

## Site de Teste (`index.html` e `testList.html`)

O projeto fornece uma forma robusta de testar as funções de `securityUtils.mjs` através de `index.html` e `testList.html`.

*   **`index.html`**: Esta é a página de interface principal para testes. Ela não apenas permite a entrada manual de dados para testar as funções de sanitização em tempo real, mas também carrega e processa automaticamente uma lista de casos de teste definidos em `testList.html`. A lógica de interatividade e o processamento dos testes estão contidos em uma tag `<script type="module">` dentro do próprio arquivo `index.html`.
*   **`testList.html`**: Este arquivo não é uma página HTML para ser visualizada diretamente no navegador. Em vez disso, ele serve como um repositório de casos de teste. `index.html` busca o conteúdo de `testList.html` e o parseia para extrair uma lista de entradas de teste e os resultados esperados após a sanitização. Cada item de teste em `testList.html` normalmente consiste em um valor de entrada e o valor que se espera como saída de uma das funções de `securityUtils.mjs`.

### Como Usar o Site de Teste:

1.  Abra o arquivo `index.html` em um navegador da web moderno que suporte módulos JavaScript.
2.  Ao carregar, `index.html` automaticamente buscará e processará os casos de teste de `testList.html`. Os resultados desses testes (Passou/Falhou) serão exibidos na página.
3.  Você pode inspecionar os resultados para verificar se as funções de `securityUtils.mjs` estão se comportando como esperado para cada caso de teste.
4.  Além dos testes automatizados, você pode usar os campos de entrada em `index.html` para testar manualmente as funções com suas próprias entradas.
5.  Para adicionar novos casos de teste ou modificar existentes, edite o arquivo `testList.html` seguindo o formato dos itens já presentes. Isso permite expandir facilmente a cobertura de testes para novas funcionalidades ou cenários.

## Como Executar o Projeto

Este projeto é construído com HTML e JavaScript do lado do cliente e não requer um servidor backend.

1.  **Clone o repositório (se aplicável):**
    ```bash
    git clone <url_do_repositorio>
    cd <diretorio_do_projeto>
    ```
2.  **Abra `index.html` no navegador:**
    *   Navegue até o diretório do projeto.
    *   Abra o arquivo `index.html` diretamente no seu navegador (ex: Google Chrome, Firefox, Safari, Edge).

## Arquivos Chave do Projeto

*   **`README.md`**: Este arquivo, fornecendo uma visão geral detalhada do projeto.
*   **`index.html`**: A página principal do site de teste, que inclui a lógica de teste (em um `<script type="module">`) e a interface do usuário para interagir com as funções de sanitização e visualizar os resultados dos testes de `testList.html`.
*   **`testList.html`**: Um arquivo HTML que não é para visualização direta, mas serve como uma fonte de dados para `index.html`, contendo uma lista de casos de teste (entradas e saídas esperadas) para as funções em `securityUtils.mjs`.
*   **`securityUtils.mjs`**: O módulo JavaScript contendo as funções de sanitização de entrada e utilidades de segurança.
*   **`style.css`**: Contém as regras de estilo para a página `index.html`, melhorando sua aparência e usabilidade.

## (Opcional) Melhorias Futuras

*   **Expandir o conjunto de funções:** Adicionar mais funções de sanitização para outros tipos de dados (ex: JSON, atributos CSS) ou contextos específicos.
*   **Validação de Dados Mais Rica:** Implementar funções de validação mais complexas (ex: formatos de e-mail, números de telefone, senhas fortes) em conjunto com a sanitização.
*   **Configuração Aprimorada:** Permitir maior configurabilidade das funções existentes (ex: níveis de sanitização, listas personalizadas de permissão/bloqueio).
*   **Documentação Detalhada de Funções:** Gerar documentação mais detalhada para cada função, possivelmente usando JSDoc.
*   **Framework de Testes Dedicado:** Integrar um framework de testes JavaScript como Jest ou Mocha para testes unitários mais robustos e relatórios de cobertura de código para `securityUtils.mjs`.
*   **Política de Segurança de Conteúdo (CSP):** Implementar e testar o uso de CSP em conjunto com as utilidades.
*   **Internacionalização (i18n):** Se aplicável, adaptar as mensagens de erro ou logs para suportar múltiplos idiomas.
*   **Teste de Mutação:** Aplicar testes de mutação para avaliar a qualidade e a robustez dos casos de teste existentes para `securityUtils.mjs`.
