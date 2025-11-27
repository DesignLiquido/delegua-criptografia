import crypto from 'crypto';

/**
 * Biblioteca de criptografia para Delégua.
 * Wrapper em português para métodos de criptografia do Node.js.
 */

/**
 * Gera um hash MD5 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash MD5 em formato hexadecimal
 */
export function md5(texto: string): string {
    return crypto.createHash('md5').update(texto).digest('hex');
}

/**
 * Gera um hash SHA-1 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-1 em formato hexadecimal
 */
export function sha1(texto: string): string {
    return crypto.createHash('sha1').update(texto).digest('hex');
}

/**
 * Gera um hash SHA-256 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-256 em formato hexadecimal
 */
export function sha256(texto: string): string {
    return crypto.createHash('sha256').update(texto).digest('hex');
}

/**
 * Gera um hash SHA-512 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-512 em formato hexadecimal
 */
export function sha512(texto: string): string {
    return crypto.createHash('sha512').update(texto).digest('hex');
}

/**
 * Gera um HMAC (Hash-based Message Authentication Code) usando SHA-256.
 * @param texto O texto a ser autenticado
 * @param chave A chave secreta para geração do HMAC
 * @returns HMAC em formato hexadecimal
 */
export function hmacSha256(texto: string, chave: string): string {
    return crypto.createHmac('sha256', chave).update(texto).digest('hex');
}

/**
 * Gera um HMAC usando SHA-512.
 * @param texto O texto a ser autenticado
 * @param chave A chave secreta para geração do HMAC
 * @returns HMAC em formato hexadecimal
 */
export function hmacSha512(texto: string, chave: string): string {
    return crypto.createHmac('sha512', chave).update(texto).digest('hex');
}

/**
 * Gera bytes aleatórios criptograficamente seguros.
 * @param tamanho Número de bytes a serem gerados
 * @returns Buffer com bytes aleatórios
 */
export function gerarBytesAleatorios(tamanho: number): Buffer {
    return crypto.randomBytes(tamanho);
}

/**
 * Gera uma string aleatória em formato hexadecimal.
 * @param tamanho Número de bytes (o resultado terá o dobro de caracteres)
 * @returns String hexadecimal aleatória
 */
export function gerarStringAleatoria(tamanho: number): string {
    return crypto.randomBytes(tamanho).toString('hex');
}

/**
 * Gera um UUID (Universally Unique Identifier) versão 4.
 * @returns UUID no formato padrão (ex: 'f47ac10b-58cc-4372-a567-0e02b2c3d479')
 */
export function gerarUuid(): string {
    return crypto.randomUUID();
}

/**
 * Codifica uma string em Base64.
 * @param texto Texto a ser codificado
 * @returns String em formato Base64
 */
export function codificarBase64(texto: string): string {
    return Buffer.from(texto, 'utf8').toString('base64');
}

/**
 * Decodifica uma string Base64.
 * @param textoBase64 String em formato Base64
 * @returns Texto decodificado
 */
export function decodificarBase64(textoBase64: string): string {
    return Buffer.from(textoBase64, 'base64').toString('utf8');
}

/**
 * Criptografa um texto usando AES-256-CBC.
 * @param texto Texto a ser criptografado
 * @param chave Chave de criptografia (deve ter 32 caracteres para AES-256)
 * @param vetorInicializacao Vetor de inicialização (IV) com 16 bytes. Se não fornecido, será gerado automaticamente.
 * @returns Objeto contendo o texto criptografado em Base64 e o IV usado
 */
export function criptografarAes256(
    texto: string, 
    chave: string, 
    vetorInicializacao?: Buffer
): { textoCriptografado: string; iv: string } {
    // Garante que a chave tenha 32 bytes (256 bits)
    const chaveBuffer = Buffer.alloc(32);
    chaveBuffer.write(chave.slice(0, 32));
    
    // Gera ou usa o IV fornecido
    const iv = vetorInicializacao || crypto.randomBytes(16);
    
    const cipher = crypto.createCipheriv('aes-256-cbc', chaveBuffer, iv);
    let criptografado = cipher.update(texto, 'utf8', 'base64');
    criptografado += cipher.final('base64');
    
    return {
        textoCriptografado: criptografado,
        iv: iv.toString('hex')
    };
}

/**
 * Descriptografa um texto usando AES-256-CBC.
 * @param textoCriptografado Texto criptografado em Base64
 * @param chave Chave de descriptografia (deve ter 32 caracteres)
 * @param iv Vetor de inicialização em formato hexadecimal
 * @returns Texto descriptografado
 */
export function descriptografarAes256(
    textoCriptografado: string, 
    chave: string, 
    iv: string
): string {
    // Garante que a chave tenha 32 bytes (256 bits)
    const chaveBuffer = Buffer.alloc(32);
    chaveBuffer.write(chave.slice(0, 32));
    
    const ivBuffer = Buffer.from(iv, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', chaveBuffer, ivBuffer);
    
    let descriptografado = decipher.update(textoCriptografado, 'base64', 'utf8');
    descriptografado += decipher.final('utf8');
    
    return descriptografado;
}

/**
 * Gera um par de chaves RSA (pública e privada).
 * @param tamanhoModulo Tamanho do módulo em bits (padrão: 2048)
 * @returns Objeto contendo as chaves pública e privada em formato PEM
 */
export function gerarParChavesRsa(tamanhoModulo: number = 2048): {
    chavePublica: string;
    chavePrivada: string;
} {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: tamanhoModulo,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    
    return {
        chavePublica: publicKey,
        chavePrivada: privateKey
    };
}

/**
 * Criptografa um texto usando uma chave pública RSA.
 * @param texto Texto a ser criptografado
 * @param chavePublica Chave pública RSA em formato PEM
 * @returns Texto criptografado em Base64
 */
export function criptografarRsa(texto: string, chavePublica: string): string {
    const buffer = Buffer.from(texto, 'utf8');
    const criptografado = crypto.publicEncrypt(chavePublica, buffer);
    return criptografado.toString('base64');
}

/**
 * Descriptografa um texto usando uma chave privada RSA.
 * @param textoCriptografado Texto criptografado em Base64
 * @param chavePrivada Chave privada RSA em formato PEM
 * @returns Texto descriptografado
 */
export function descriptografarRsa(textoCriptografado: string, chavePrivada: string): string {
    const buffer = Buffer.from(textoCriptografado, 'base64');
    const descriptografado = crypto.privateDecrypt(chavePrivada, buffer);
    return descriptografado.toString('utf8');
}

/**
 * Assina digitalmente um texto usando uma chave privada RSA.
 * @param texto Texto a ser assinado
 * @param chavePrivada Chave privada RSA em formato PEM
 * @returns Assinatura digital em Base64
 */
export function assinarRsa(texto: string, chavePrivada: string): string {
    const sign = crypto.createSign('SHA256');
    sign.update(texto);
    sign.end();
    return sign.sign(chavePrivada, 'base64');
}

/**
 * Verifica uma assinatura digital usando uma chave pública RSA.
 * @param texto Texto original
 * @param assinatura Assinatura digital em Base64
 * @param chavePublica Chave pública RSA em formato PEM
 * @returns true se a assinatura for válida, false caso contrário
 */
export function verificarAssinaturaRsa(
    texto: string, 
    assinatura: string, 
    chavePublica: string
): boolean {
    const verify = crypto.createVerify('SHA256');
    verify.update(texto);
    verify.end();
    return verify.verify(chavePublica, assinatura, 'base64');
}

/**
 * Deriva uma chave a partir de uma senha usando PBKDF2.
 * @param senha Senha base
 * @param sal Salt (valor aleatório para aumentar segurança)
 * @param iteracoes Número de iterações (padrão: 100000)
 * @param tamanhoChave Tamanho da chave derivada em bytes (padrão: 32)
 * @returns Chave derivada em formato hexadecimal
 */
export function derivarChavePbkdf2(
    senha: string,
    sal: string,
    iteracoes: number = 100000,
    tamanhoChave: number = 32
): string {
    return crypto.pbkdf2Sync(senha, sal, iteracoes, tamanhoChave, 'sha256').toString('hex');
}

/**
 * Gera um salt aleatório para uso em derivação de chaves.
 * @param tamanho Tamanho do salt em bytes (padrão: 16)
 * @returns Salt em formato hexadecimal
 */
export function gerarSalt(tamanho: number = 16): string {
    return crypto.randomBytes(tamanho).toString('hex');
}

// Exportação padrão com todas as funções
export default {
    md5,
    sha1,
    sha256,
    sha512,
    hmacSha256,
    hmacSha512,
    gerarBytesAleatorios,
    gerarStringAleatoria,
    gerarUuid,
    codificarBase64,
    decodificarBase64,
    criptografarAes256,
    descriptografarAes256,
    gerarParChavesRsa,
    criptografarRsa,
    descriptografarRsa,
    assinarRsa,
    verificarAssinaturaRsa,
    derivarChavePbkdf2,
    gerarSalt
};