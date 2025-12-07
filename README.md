# delegua-criptografia

Biblioteca de criptografia para Delégua e JavaScript com nomes de métodos em português.

Esta biblioteca oferece funcionalidades criptográficas unificadas que funcionam tanto em Node.js quanto em navegadores, com uma interface em português para facilitar o uso por desenvolvedores que programam em Delégua.

## Instalação

```bash
npm install @designliquido/delegua-criptografia
```

## Uso com Delégua

```delegua
var criptografia = importar('criptografia')

// Gerar hash SHA-256
var hash = criptografia.sha256("Olá Mundo")
escreva(hash)

// Gerar UUID
var id = criptografia.gerarUuid()
escreva(id)

// Codificar em Base64
var textoBase64 = criptografia.codificarBase64("Texto secreto")
escreva(textoBase64)

// Criptografar com AES-256-GCM
var resultado = criptografia.criptografarAes256("mensagem secreta", "minha-chave-super-secreta-aqui!")
escreva(resultado.textoCriptografado)
escreva(resultado.iv)

// Descriptografar com AES-256-GCM (mesma API em Node.js e navegador!)
var textoOriginal = criptografia.descriptografarAes256(
    resultado.textoCriptografado,
    "minha-chave-super-secreta-aqui!",
    resultado.iv
)
escreva(textoOriginal)

// Cifras clássicas (educacionais)
var cifrado = criptografia.rot13("Hello World")
escreva(cifrado) // "Uryyb Jbeyq"
```

## Uso com JavaScript/TypeScript

### CommonJS

```javascript
const criptografia = require('@designliquido/delegua-criptografia');

// Gerar hash SHA-256
const hash = await criptografia.sha256(undefined, "Olá Mundo");
console.log(hash);

// Gerar string aleatória
const textoAleatorio = criptografia.gerarTextoAleatorio(undefined, 16);
console.log(textoAleatorio);
```

### ES Modules

```typescript
import { sha256, gerarUuid, criptografarAes256 } from '@designliquido/delegua-criptografia';

// Gerar hash (funções de hash são assíncronas)
const hash = await sha256(undefined, "Olá Mundo");
console.log(hash);

// Gerar UUID
const id = gerarUuid();
console.log(id);

// Criptografar
const resultado = await criptografarAes256(undefined, "dados sensíveis", "chave-secreta-32-caracteres!");
console.log(resultado);
```

## Funções Disponíveis

### Funções de Hash

- **`md5(interpretador: any, texto: string): string`**  
  Gera um hash MD5 (não recomendado para segurança, apenas para checksums)

- **`sha1(interpretador: any, texto: string): Promise<string>`**  
  Gera um hash SHA-1

- **`sha256(interpretador: any, texto: string): Promise<string>`**  
  Gera um hash SHA-256 (recomendado)

- **`sha512(interpretador: any, texto: string): Promise<string>`**  
  Gera um hash SHA-512

### HMAC (Hash-based Message Authentication Code)

- **`hmacSha256(interpretador: any, texto: string, chave: string): Promise<string>`**  
  Gera um HMAC usando SHA-256

- **`hmacSha512(interpretador: any, texto: string, chave: string): Promise<string>`**  
  Gera um HMAC usando SHA-512

### Geração de Dados Aleatórios

- **`gerarBytesAleatorios(interpretador: any, tamanho: number): Uint8Array`**  
  Gera bytes aleatórios criptograficamente seguros

- **`gerarTextoAleatorio(interpretador: any, tamanho: number): string`**  
  Gera um texto aleatório composto por caracteres hexadecimais

- **`gerarUuid(): string`**  
  Gera um UUID versão 4

- **`gerarSalt(interpretador?: any, tamanho?: number): string`**  
  Gera um salt para uso em derivação de chaves (padrão: 16 bytes)

### Codificação Base64

- **`codificarBase64(interpretador: any, texto: string): string`**  
  Codifica texto em Base64

- **`decodificarBase64(interpretador: any, textoBase64: string): string`**  
  Decodifica texto de Base64

### Criptografia Simétrica (AES-256-GCM)

- **`criptografarAes256(interpretador: any, texto: string, chave: string, vetorInicializacao?: Uint8Array): Promise<{ textoCriptografado: string; iv: string }>`**  
  Criptografa texto usando AES-256-GCM (modo autenticado). A chave deve ter 32 caracteres. O authTag é automaticamente incluído no resultado.

- **`descriptografarAes256(interpretador: { resolverValor: (valor: any) => any }, textoCriptografado: string, chave: string, iv: string): Promise<string>`**  
  Descriptografa texto usando AES-256-GCM. O authTag é automaticamente extraído do texto criptografado. API unificada para Node.js e navegadores.

### Criptografia Assimétrica (RSA)

- **`gerarParChavesRsa(interpretador: any, tamanhoModulo?: number): Promise<{ chavePublica: any; chavePrivada: any }>`**  
  Gera um par de chaves RSA-OAEP para criptografia/descriptografia (padrão: 2048 bits). Retorna strings PEM no Node.js e objetos CryptoKey em navegadores.

- **`gerarParChavesRsaAssinatura(interpretador: any, tamanhoModulo?: number): Promise<{ chavePublica: any; chavePrivada: any }>`**  
  Gera um par de chaves RSA-PSS para assinatura digital (padrão: 2048 bits). **Use esta função para assinatura em navegadores**.

- **`criptografarRsa(interpretador: any, texto: string, chavePublica: any): Promise<string>`**  
  Criptografa texto usando chave pública RSA-OAEP

- **`descriptografarRsa(interpretador: { resolverValor: (valor: any) => any }, textoCriptografado: string, chavePrivada: any): Promise<string>`**  
  Descriptografa texto usando chave privada RSA-OAEP

### Assinatura Digital (RSA-PSS)

- **`assinarRsa(interpretador: any, texto: string, chavePrivada: any): Promise<string>`**  
  Assina digitalmente um texto usando chave privada RSA. **Em navegadores, use chaves geradas com `gerarParChavesRsaAssinatura()`**.

- **`verificarAssinaturaRsa(interpretador: any, texto: string, assinatura: string, chavePublica: any): Promise<boolean>`**  
  Verifica uma assinatura digital usando chave pública RSA. **Em navegadores, use chaves geradas com `gerarParChavesRsaAssinatura()`**.

### Derivação de Chaves

- **`derivarChavePbkdf2(interpretador: any, senha: string, sal: string, iteracoes?: number, tamanhoChave?: number): Promise<string>`**  
  Deriva uma chave a partir de uma senha usando PBKDF2 (padrão: 100.000 iterações, 32 bytes)

### Cifras Clássicas (Educacionais) 🎓

⚠️ **IMPORTANTE**: As funções abaixo são apenas para fins educacionais e demonstração de conceitos de criptografia. **NÃO devem ser usadas para proteger dados sensíveis reais!**

- **`cifrarXor(interpretador: any, texto: string, chave: string): string`**  
  Cifra texto usando operação XOR bit a bit. Retorna resultado em hexadecimal.

- **`decifrarXor(interpretador: any, textoHex: string, chave: string): string`**  
  Decifra texto cifrado com XOR. Como XOR é simétrico, a operação é reversível com a mesma chave.

- **`rot13(interpretador: any, texto: string): string`**  
  Aplica ROT13 (desloca letras em 13 posições). Aplicar duas vezes retorna o original.

- **`rotN(interpretador: any, texto: string, deslocamento: number): string`**  
  Cifra de César com deslocamento customizado. Generalização do ROT13.

- **`decifrarRotN(interpretador: any, texto: string, deslocamento: number): string`**  
  Decifra texto cifrado com ROT-N aplicando deslocamento inverso.

#### Menino do Acre

Este módulo implementa uma cifra de substituição inspirada nos símbolos criados pelo Menino do Acre, mas usando apenas caracteres já existentes no **Unicode**. São suportados três temas:

- **Runico** → usa o bloco de Runas (U+16A0–U+16FF)  
- **Alquimico** → usa o bloco de Símbolos Alquímicos (U+1F700–U+1F77F)  
- **Hibrido** → vogais em runas, consoantes em símbolos alquímicos

Aqui implementamos nossa versão da criptografia do Menino do Acre com fins educacionais e culturais. 

Exemplos de utilização:

```js
// Importar módulo de criptografia
var criptografia = importar('criptografia')

// Texto original
var texto = "delegua"

// Criptografar com tema rúnico
var resultadoRunico = criptografia.criptografarEmMeninoDoAcre({}, texto, { tema: "runico" })
escreva(resultadoRunico)

// Descriptografar com tema rúnico
var originalRunico = criptografia.descriptografarDeMeninoDoAcre({}, resultadoRunico, { tema: "runico" })
escreva(originalRunico)

// Criptografar com tema alquímico
var resultadoAlquimico = criptografia.criptografarEmMeninoDoAcre({}, texto, { tema: "alquimico" })
escreva(resultadoAlquimico)

// Descriptografar com tema alquímico
var originalAlquimico = criptografia.descriptografarDeMeninoDoAcre({}, resultadoAlquimico, { tema: "alquimico" })
escreva(originalAlquimico)

// Criptografar com tema híbrido (vogais → runas, consoantes → alquímicos)
var resultadoHibrido = criptografia.criptografarEmMeninoDoAcre({}, texto, { tema: "hibrido" })
escreva(resultadoHibrido)

// Descriptografar com tema híbrido
var originalHibrido = criptografia.descriptografarDeMeninoDoAcre({}, resultadoHibrido, { tema: "hibrido" })
escreva(originalHibrido)
```

## Exemplos Completos

### Exemplo 1: Hash de senha com salt

```javascript
const { sha256, gerarSalt } = require('@designliquido/delegua-criptografia');

const senha = "minha_senha_123";
const sal = gerarSalt(undefined);
const senhaHash = await sha256(undefined, senha + sal);

console.log("Salt:", sal);
console.log("Hash:", senhaHash);
```

### Exemplo 2: Criptografia simétrica AES-256-GCM

```javascript
const { criptografarAes256, descriptografarAes256 } = require('@designliquido/delegua-criptografia');

const interpretador = { resolverValor: (v) => v };

const mensagem = "Dados muito secretos";
const chave = "minha-chave-super-secreta-aqui!"; // 32 caracteres

// Criptografar
const resultado = await criptografarAes256(undefined, mensagem, chave);
console.log("Criptografado:", resultado.textoCriptografado);
console.log("IV:", resultado.iv);

// Descriptografar - mesma API em Node.js e navegador!
const mensagemOriginal = await descriptografarAes256(
    interpretador,
    resultado.textoCriptografado,
    chave,
    resultado.iv
);
console.log("Descriptografado:", mensagemOriginal);
```

### Exemplo 3: Criptografia assimétrica RSA (Node.js e Navegador)

```javascript
const { 
    gerarParChavesRsa, 
    criptografarRsa, 
    descriptografarRsa 
} = require('@designliquido/delegua-criptografia');

const interpretador = { resolverValor: (v) => v };

// Gerar par de chaves para CRIPTOGRAFIA
const { chavePublica, chavePrivada } = await gerarParChavesRsa(undefined, 2048);

const mensagem = "Mensagem confidencial";

// Criptografar com chave pública
const criptografado = await criptografarRsa(undefined, mensagem, chavePublica);
console.log("Criptografado:", criptografado);

// Descriptografar com chave privada
const descriptografado = await descriptografarRsa(interpretador, criptografado, chavePrivada);
console.log("Descriptografado:", descriptografado);
```

### Exemplo 4: Assinatura digital (Node.js e Navegador)

```javascript
const { 
    gerarParChavesRsaAssinatura,  // Use esta função para assinatura!
    assinarRsa, 
    verificarAssinaturaRsa 
} = require('@designliquido/delegua-criptografia');

// Gerar par de chaves para ASSINATURA
const { chavePublica, chavePrivada } = await gerarParChavesRsaAssinatura(undefined, 2048);

const documento = "Contrato importante";

// Assinar documento
const assinatura = await assinarRsa(undefined, documento, chavePrivada);
console.log("Assinatura:", assinatura);

// Verificar assinatura
const valida = await verificarAssinaturaRsa(undefined, documento, assinatura, chavePublica);
console.log("Assinatura válida:", valida); // true

// Tentar verificar com documento alterado
const documentoAlterado = "Contrato importante modificado";
const validaAlterado = await verificarAssinaturaRsa(undefined, documentoAlterado, assinatura, chavePublica);
console.log("Assinatura válida (alterado):", validaAlterado); // false
```

### Exemplo 5: Derivação de chave com PBKDF2

```javascript
const { derivarChavePbkdf2, gerarSalt } = require('@designliquido/delegua-criptografia');

const senha = "senha_do_usuario";
const sal = gerarSalt(undefined);

// Derivar chave da senha
const chaveDerivada = await derivarChavePbkdf2(undefined, senha, sal, 100000, 32);

console.log("Salt:", sal);
console.log("Chave derivada:", chaveDerivada);

// Essa chave pode ser usada para criptografia AES-256
```

### Exemplo 6: Uso completo em Delégua

```delegua
var criptografia = importar('criptografia')

// Criptografia e descriptografia
var resultado = criptografia.criptografarAes256("mensagem secreta", "minha-chave-super-secreta-aqui!")
escreva("Criptografado: " + resultado.textoCriptografado)

var textoOriginal = criptografia.descriptografarAes256(
    resultado.textoCriptografado,
    "minha-chave-super-secreta-aqui!",
    resultado.iv
)
escreva("Descriptografado: " + textoOriginal)

// Assinatura digital - usar gerarParChavesRsaAssinatura em navegadores
var parAssinatura = criptografia.gerarParChavesRsaAssinatura(2048)
var documento = "Contrato importante"
var assinatura = criptografia.assinarRsa(documento, parAssinatura.chavePrivada)
var valida = criptografia.verificarAssinaturaRsa(documento, assinatura, parAssinatura.chavePublica)
escreva("Assinatura válida: " + valida)
```

### Exemplo 7: Cifras clássicas (Educacionais) 🎓

```javascript
const { cifrarXor, decifrarXor, rot13, rotN, decifrarRotN } = require('@designliquido/delegua-criptografia');

// XOR - Operação bit a bit
const mensagem = "Olá Mundo";
const chave = "segredo";

const xorCifrado = cifrarXor(undefined, mensagem, chave);
console.log("XOR Cifrado:", xorCifrado); // Hexadecimal

const xorDecifrado = decifrarXor(undefined, xorCifrado, chave);
console.log("XOR Decifrado:", xorDecifrado); // "Olá Mundo"

// ROT13 - Desloca 13 posições
const textoRot13 = "Hello World";
const cifradoRot13 = rot13(undefined, textoRot13);
console.log("ROT13:", cifradoRot13); // "Uryyb Jbeyq"

// Aplicar novamente para decifrar
const originalRot13 = rot13(undefined, cifradoRot13);
console.log("Original:", originalRot13); // "Hello World"

// ROT-N (Cifra de César) - Deslocamento customizado
const textoCesar = "ATAQUE AO AMANHECER";
const deslocamento = 3;

const cifradoCesar = rotN(undefined, textoCesar, deslocamento);
console.log("César (ROT-3):", cifradoCesar); // "DWDTXH DR DPDQKHFHU"

const originalCesar = decifrarRotN(undefined, cifradoCesar, deslocamento);
console.log("Decifrado:", originalCesar); // "ATAQUE AO AMANHECER"
```

### Exemplo 8: Aplicações educacionais em Delégua

```delegua
var criptografia = importar('criptografia')

// Demonstração de ROT13
escreva("=== Demonstração ROT13 ===")
var mensagem = "The quick brown fox"
var cifrado = criptografia.rot13(mensagem)
escreva("Original: " + mensagem)
escreva("Cifrado:  " + cifrado)
escreva("Decifrado: " + criptografia.rot13(cifrado))

// Demonstração de Cifra de César
escreva("\n=== Cifra de César ===")
var segredo = "MENSAGEM SECRETA"
para (var d = 1; d <= 25; d++) {
    var resultado = criptografia.rotN(segredo, d)
    escreva("ROT-" + d + ": " + resultado)
}

// Demonstração de XOR
escreva("\n=== Cifra XOR ===")
var texto = "Dados importantes"
var chave = "chave123"
var xorCifrado = criptografia.cifrarXor(texto, chave)
escreva("Cifrado (hex): " + xorCifrado)
escreva("Decifrado: " + criptografia.decifrarXor(xorCifrado, chave))
```

### Exemplo 9: Quebrando cifras clássicas (Análise Criptográfica) 🔓

```javascript
const { rot13, rotN, cifrarXor } = require('@designliquido/delegua-criptografia');

// Exemplo educacional: quebrar ROT-N por força bruta
function quebrarRotN(textoCifrado) {
    console.log("Tentando quebrar:", textoCifrado);
    console.log("\nTodas as possibilidades (ROT-1 até ROT-25):\n");
    
    for (let deslocamento = 1; deslocamento <= 25; deslocamento++) {
        const tentativa = rotN(undefined, textoCifrado, -deslocamento);
        console.log(`ROT-${deslocamento}: ${tentativa}`);
    }
}

// Texto cifrado desconhecido
const cifrado = "Khoor Zruog"; // "Hello World" com ROT-3
quebrarRotN(cifrado);

// Análise de frequência para XOR (mais avançado)
function analisarXor(textoCifradoHex) {
    console.log("\n=== Análise de Frequência XOR ===");
    console.log("Texto cifrado (hex):", textoCifradoHex);
    
    // Converter hex para bytes
    const bytes = [];
    for (let i = 0; i < textoCifradoHex.length; i += 2) {
        bytes.push(parseInt(textoCifradoHex.substr(i, 2), 16));
    }
    
    // Analisar padrões (exemplo simplificado)
    console.log("\nPrimeiros bytes:", bytes.slice(0, 10));
    console.log("\nDica: Em texto real, espaços (0x20) são comuns.");
    console.log("Se você XOR um byte com 0x20, pode descobrir a chave!");
}

const exemplo = cifrarXor(undefined, "teste teste teste", "k");
analisarXor(exemplo);
```

## Compatibilidade entre Ambientes

Esta biblioteca foi projetada para funcionar de forma **unificada** em Node.js e navegadores:

### Node.js
- Usa o módulo `crypto` nativo
- Retorna chaves RSA como strings PEM
- Suporta todos os algoritmos nativamente

### Navegadores
- Usa a Web Crypto API (`crypto.subtle`)
- Retorna chaves RSA como objetos `CryptoKey`
- **Importante**: RSA-OAEP (criptografia) e RSA-PSS (assinatura) usam chaves diferentes
  - Use `gerarParChavesRsa()` para criptografia/descriptografia
  - Use `gerarParChavesRsaAssinatura()` para assinatura/verificação

### API Unificada AES-256-GCM
A criptografia AES-256 tem **API idêntica** em ambos os ambientes:
- O `authTag` é automaticamente incluído no `textoCriptografado`
- Não é necessário passar o `authTag` separadamente
- Mesma função e mesmos parâmetros em Node.js e navegadores

## Segurança

⚠️ **Notas importantes de segurança:**

### Algoritmos Seguros para Produção

- **SHA-256** ou **SHA-512** para hashing seguro
- **AES-256-GCM** para criptografia simétrica (é mais seguro que CBC pois fornece autenticação integrada)
- **RSA-2048** ou superior para criptografia assimétrica
- **HMAC-SHA256/512** para verificar integridade e autenticidade de mensagens
- **PBKDF2** com 100.000+ iterações para derivar chaves de senhas

### Algoritmos NÃO Seguros (Apenas Educacionais)

- **MD5** e **SHA-1**: Vulneráveis a colisões, use apenas para checksums não-críticos
- **ROT13**: Trivialmente quebrável, apenas para ofuscação leve ou jogos
- **XOR simples**: Vulnerável a análise de frequência e ataques conhecidos
- **ROT-N (Cifra de César)**: Apenas 25 possibilidades, quebrável por força bruta em segundos

### Por Que Cifras Clássicas São Fracas?

#### ROT13 e Cifra de César
- Apenas **25 possibilidades** (ROT-1 até ROT-25)
- Pode ser quebrado por **força bruta** em menos de 1 segundo
- Não usa chave secreta verdadeira
- **Exemplo**: Se você vê "Uryyb", teste ROT-1, ROT-2... até encontrar "Hello"

#### XOR Simples
- Vulnerável a **ataques de texto conhecido** (_known-plaintext attack_)
- Se o atacante sabe parte do texto original, pode descobrir a chave
- **Análise de frequência**: Letras comuns (como 'e', 'a') revelam padrões
- **Exemplo**: Se "hello" vira "2d0b0f", e sabemos que 'h' = 0x68, podemos calcular a chave

#### Por Que São Úteis Para Aprender? 🎓
1. **Conceitos fundamentais**: Ensinam substituição, transposição, operações bit a bit
2. **Fáceis de entender**: Não requerem matemática avançada
3. **Demonstram fraquezas**: Mostram por que criptografia moderna é complexa
4. **Base histórica**: ROT13 vem do ROT-47, usado no Unix; César foi usado há 2000 anos!

### Melhores Práticas

- Para **armazenar senhas**: Use **PBKDF2** com _salt_ único por senha (ou bcrypt/scrypt/argon2)
- Para **criptografia de dados**: Use **AES-256-GCM** com chaves de 32 caracteres
- Para **chaves AES**: Use `derivarChavePbkdf2` ou `gerarTextoAleatorio` para gerar chaves fortes
- Para **verificar integridade**: Use **HMAC-SHA256**
- **Nunca** compartilhe chaves privadas RSA
- **Nunca** reutilize o mesmo IV (vetor de inicialização) com a mesma chave AES
- Em navegadores, **sempre use funções separadas** para gerar chaves de criptografia vs. assinatura

### Quando Usar Cada Algoritmo

| Uso                   | Algoritmo Recomendado | Evitar                  |
|-----------------------|-----------------------|-------------------------|
| Senha do usuário      | PBKDF2 (100k+ iter.)  | MD5, SHA-1 sem salt     |
| Criptografar arquivo  | AES-256-GCM           | XOR, ROT13              |
| Assinatura digital    | RSA-PSS 2048+         | Nenhuma assinatura      |
| Verificar integridade | HMAC-SHA256           | CRC32, checksum simples |
| Aprender conceitos    | ROT13, XOR, César     | (Usar em produção)      |
| Ofuscação leve*       | Base64 + ROT13        | (Para dados sensíveis)  |

*Ofuscação não é segurança! Use apenas para tornar dados não-óbvios, nunca para proteção real.

## Estrutura do Projeto

```
delegua-criptografia/
├── fontes/
|   ├── aes.ts 
|   ├── aleatorios.ts 
|   ├── base64.ts 
|   ├── comum.ts 
│   ├── delegua-modulo.ts      # Manifesto do módulo
|   ├── educacionais.ts 
|   ├── hashes.ts 
│   ├── index.ts               # Ponto de entrada
|   ├── menino-do-acre.ts 
|   ├── pbkdf2.ts 
|   ├── rsa.ts 
|   └── salt.ts
├── testes/
│   ├── index.test.ts          # Testes unitários
|   └── menino-do-acre.test.ts
├── dist/                      # Arquivos compilados (gerados)
├── package.json
├── tsconfig.json
└── README.md
```

## Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir _issues_ e _pull requests_.

## Licença

MIT License - veja o arquivo LICENSE para mais detalhes.

## Créditos

Desenvolvido pela [Design Líquido](https://github.com/DesignLiquido) como parte do ecossistema Delégua.