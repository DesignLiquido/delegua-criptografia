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

### Menino do Acre

Este módulo implementa uma cifra de substituição inspirada nos símbolos criados pelo Menino do Acre, mas usando apenas caracteres já existentes no **Unicode**. São suportados três temas:

- **Runico** → usa o bloco de Runas (U+16A0–U+16FF)  
- **Alquimico** → usa o bloco de Símbolos Alquímicos (U+1F700–U+1F77F)  
- **Hibrido** → vogais em runas, consoantes em símbolos alquímicos 

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

- **MD5 e SHA-1** não devem ser usados para fins de segurança críticos, apenas para checksums simples
- Use **SHA-256** ou **SHA-512** para hashing seguro
- Para armazenar senhas, sempre use **salt** único por senha e considere usar **PBKDF2** ou bibliotecas especializadas como bcrypt
- Chaves AES-256 devem ter **exatamente 32 caracteres** (256 bits)
- Nunca compartilhe chaves privadas RSA
- Use **HMAC** quando precisar verificar a integridade e autenticidade de mensagens
- **AES-256-GCM** é mais seguro que CBC pois fornece autenticação integrada
- Em navegadores, **sempre use funções separadas** para gerar chaves de criptografia vs. assinatura

## Estrutura do Projeto
```
delegua-criptografia/
├── fontes/
│   ├── delegua-modulo.ts  # Manifesto do módulo
│   └── index.ts           # Código principal
├── testes/
│   └── index.test.ts      # Testes unitários
├── dist/                  # Arquivos compilados (gerados)
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