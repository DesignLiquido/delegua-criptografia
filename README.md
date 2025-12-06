# delegua-criptografia

Biblioteca de criptografia para Delégua e JavaScript com nomes de métodos em português.

Esta biblioteca encapsula funcionalidades do módulo `crypto` nativo do Node.js, oferecendo uma interface em português para facilitar o uso por desenvolvedores que programam em Delégua.

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

// Criptografar com AES-256
var resultado = criptografia.criptografarAes256("mensagem secreta", "minha-chave-super-secreta-aqui!")
escreva(resultado.textoCriptografado)

// Descriptografar com AES-256
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
const hash = criptografia.sha256("Olá Mundo");
console.log(hash);

// Gerar string aleatória
const textoAleatorio = criptografia.gerarTextoAleatorio(16);
console.log(textoAleatorio);
```

### ES Modules

```typescript
import { sha256, gerarUuid, criptografarAes256 } from '@designliquido/delegua-criptografia';

// Gerar hash
const hash = sha256("Olá Mundo");
console.log(hash);

// Gerar UUID
const id = gerarUuid();
console.log(id);

// Criptografar
const resultado = criptografarAes256("dados sensíveis", "chave-secreta-32-caracteres!");
console.log(resultado);
```

## Funções Disponíveis

### Funções de Hash

- **`md5(texto: string): string`**  
  Gera um hash MD5 (não recomendado para segurança, apenas para checksums)

- **`sha1(texto: string): string`**  
  Gera um hash SHA-1

- **`sha256(texto: string): string`**  
  Gera um hash SHA-256 (recomendado)

- **`sha512(texto: string): string`**  
  Gera um hash SHA-512

### HMAC (Hash-based Message Authentication Code)

- **`hmacSha256(texto: string, chave: string): string`**  
  Gera um HMAC usando SHA-256

- **`hmacSha512(texto: string, chave: string): string`**  
  Gera um HMAC usando SHA-512

### Geração de Dados Aleatórios

- **`gerarBytesAleatorios(tamanho: number): Buffer`**  
  Gera bytes aleatórios criptograficamente seguros

- **`gerarTextoAleatorio(tamanho: number): string`**  
  Gera um texto aleatório composto por caracteres hexadecimais

- **`gerarUuid(): string`**  
  Gera um UUID versão 4

- **`gerarSalt(tamanho?: number): string`**  
  Gera um salt para uso em derivação de chaves (padrão: 16 bytes)

### Codificação Base64

- **`codificarBase64(texto: string): string`**  
  Codifica texto em Base64

- **`decodificarBase64(textoBase64: string): string`**  
  Decodifica texto de Base64

### Criptografia Simétrica (AES-256)

- **`criptografarAes256(texto: string, chave: string, vetorInicializacao?: Buffer): { textoCriptografado: string; iv: string }`**  
  Criptografa texto usando AES-256-CBC. A chave deve ter 32 caracteres.

- **`descriptografarAes256(textoCriptografado: string, chave: string, iv: string): string`**  
  Descriptografa texto usando AES-256-CBC

### Criptografia Assimétrica (RSA)

- **`gerarParChavesRsa(tamanhoModulo?: number): { chavePublica: string; chavePrivada: string }`**  
  Gera um par de chaves RSA (padrão: 2048 bits)

- **`criptografarRsa(texto: string, chavePublica: string): string`**  
  Criptografa texto usando chave pública RSA

- **`descriptografarRsa(textoCriptografado: string, chavePrivada: string): string`**  
  Descriptografa texto usando chave privada RSA

### Assinatura Digital

- **`assinarRsa(texto: string, chavePrivada: string): string`**  
  Assina digitalmente um texto usando chave privada RSA

- **`verificarAssinaturaRsa(texto: string, assinatura: string, chavePublica: string): boolean`**  
  Verifica uma assinatura digital usando chave pública RSA

### Derivação de Chaves

- **`derivarChavePbkdf2(senha: string, sal: string, iteracoes?: number, tamanhoChave?: number): string`**  
  Deriva uma chave a partir de uma senha usando PBKDF2 (padrão: 100.000 iterações, 32 bytes)

## Exemplos Completos

### Exemplo 1: Hash de senha com salt

```javascript
const { sha256, gerarSalt } = require('@designliquido/delegua-criptografia');

const senha = "minha_senha_123";
const sal = gerarSalt();
const senhaHash = sha256(senha + sal);

console.log("Salt:", sal);
console.log("Hash:", senhaHash);
```

### Exemplo 2: Criptografia simétrica AES-256

```javascript
const { criptografarAes256, descriptografarAes256 } = require('@designliquido/delegua-criptografia');

const mensagem = "Dados muito secretos";
const chave = "minha-chave-super-secreta-aqui!"; // 32 caracteres

// Criptografar
const resultado = criptografarAes256(mensagem, chave);
console.log("Criptografado:", resultado.textoCriptografado);
console.log("IV:", resultado.iv);

// Descriptografar
const mensagemOriginal = descriptografarAes256(
    resultado.textoCriptografado,
    chave,
    resultado.iv
);
console.log("Descriptografado:", mensagemOriginal);
```

### Exemplo 3: Criptografia assimétrica RSA

```javascript
const { 
    gerarParChavesRsa, 
    criptografarRsa, 
    descriptografarRsa 
} = require('@designliquido/delegua-criptografia');

// Gerar par de chaves
const { chavePublica, chavePrivada } = gerarParChavesRsa(2048);

const mensagem = "Mensagem confidencial";

// Criptografar com chave pública
const criptografado = criptografarRsa(mensagem, chavePublica);
console.log("Criptografado:", criptografado);

// Descriptografar com chave privada
const descriptografado = descriptografarRsa(criptografado, chavePrivada);
console.log("Descriptografado:", descriptografado);
```

### Exemplo 4: Assinatura digital

```javascript
const { 
    gerarParChavesRsa, 
    assinarRsa, 
    verificarAssinaturaRsa 
} = require('@designliquido/delegua-criptografia');

const { chavePublica, chavePrivada } = gerarParChavesRsa();

const documento = "Contrato importante";

// Assinar documento
const assinatura = assinarRsa(documento, chavePrivada);
console.log("Assinatura:", assinatura);

// Verificar assinatura
const valida = verificarAssinaturaRsa(documento, assinatura, chavePublica);
console.log("Assinatura válida:", valida); // true

// Tentar verificar com documento alterado
const documentoAlterado = "Contrato importante modificado";
const validaAlterado = verificarAssinaturaRsa(documentoAlterado, assinatura, chavePublica);
console.log("Assinatura válida (alterado):", validaAlterado); // false
```

### Exemplo 5: Derivação de chave com PBKDF2

```javascript
const { derivarChavePbkdf2, gerarSalt } = require('@designliquido/delegua-criptografia');

const senha = "senha_do_usuario";
const sal = gerarSalt();

// Derivar chave da senha
const chaveDerivada = derivarChavePbkdf2(senha, sal, 100000, 32);

console.log("Salt:", sal);
console.log("Chave derivada:", chaveDerivada);

// Essa chave pode ser usada para criptografia AES-256
```

## Segurança

⚠️ **Notas importantes de segurança:**

- **MD5 e SHA-1** não devem ser usados para fins de segurança críticos, apenas para checksums simples
- Use **SHA-256** ou **SHA-512** para hashing seguro
- Para armazenar senhas, sempre use **salt** único por senha e considere usar **PBKDF2** ou bibliotecas especializadas como bcrypt
- Chaves AES-256 devem ter **exatamente 32 caracteres** (256 bits)
- Nunca compartilhe chaves privadas RSA
- Use **HMAC** quando precisar verificar a integridade e autenticidade de mensagens

## Estrutura do Projeto

```
delegua-criptografia/
├── fontes/
    ├── delegua-modulo.ts  # Manifesto do módulo, usado pelo núcleo e ferramentas para entender tipos e documentação
│   └── index.ts           # Código principal
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