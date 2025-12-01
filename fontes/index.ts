/**
 * Biblioteca de criptografia para Delégua.
 * Compatível com Node.js e navegadores.
 */

// Detecta o ambiente
const isNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
const isBrowser = typeof globalThis !== 'undefined' && typeof (globalThis as any).window !== 'undefined';

// Importa crypto do Node.js apenas se estiver em ambiente Node
let nodeCrypto: any = null;
if (isNode) {
    nodeCrypto = require('crypto');
}

/**
 * Converte ArrayBuffer para string hexadecimal
 */
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Converte string para ArrayBuffer
 */
function stringToBuffer(str: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

/**
 * Converte ArrayBuffer para string
 */
function bufferToString(buffer: ArrayBuffer): string {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

/**
 * Implementação pura de MD5 em TypeScript
 */
function md5Pure(text: string): string {
    // Converte string para bytes UTF-8
    const utf8Bytes: number[] = [];
    for (let i = 0; i < text.length; i++) {
        let charCode = text.charCodeAt(i);
        if (charCode < 0x80) {
            utf8Bytes.push(charCode);
        } else if (charCode < 0x800) {
            utf8Bytes.push(0xc0 | (charCode >> 6), 0x80 | (charCode & 0x3f));
        } else if (charCode < 0xd800 || charCode >= 0xe000) {
            utf8Bytes.push(0xe0 | (charCode >> 12), 0x80 | ((charCode >> 6) & 0x3f), 0x80 | (charCode & 0x3f));
        } else {
            i++;
            charCode = 0x10000 + (((charCode & 0x3ff) << 10) | (text.charCodeAt(i) & 0x3ff));
            utf8Bytes.push(
                0xf0 | (charCode >> 18),
                0x80 | ((charCode >> 12) & 0x3f),
                0x80 | ((charCode >> 6) & 0x3f),
                0x80 | (charCode & 0x3f)
            );
        }
    }

    // Adiciona padding
    const msgLength = utf8Bytes.length;
    const bitLength = msgLength * 8;
    utf8Bytes.push(0x80);
    
    while (utf8Bytes.length % 64 !== 56) {
        utf8Bytes.push(0x00);
    }
    
    // Adiciona comprimento da mensagem (64 bits, little-endian)
    for (let i = 0; i < 8; i++) {
        utf8Bytes.push((bitLength >>> (i * 8)) & 0xff);
    }

    // Constantes MD5
    const K = new Array(64);
    for (let i = 0; i < 64; i++) {
        K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
    }

    // Shifts por rodada
    const shifts = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];

    // Inicialização
    let a = 0x67452301;
    let b = 0xefcdab89;
    let c = 0x98badcfe;
    let d = 0x10325476;

    // Funções auxiliares
    const rotateLeft = (x: number, n: number) => (x << n) | (x >>> (32 - n));
    const toUint32 = (x: number) => x >>> 0;

    // Processa cada bloco de 512 bits (64 bytes)
    for (let offset = 0; offset < utf8Bytes.length; offset += 64) {
        const block = utf8Bytes.slice(offset, offset + 64);
        const M = new Array(16);
        
        // Converte bytes para words (little-endian)
        for (let i = 0; i < 16; i++) {
            M[i] = block[i * 4] | (block[i * 4 + 1] << 8) | (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
        }

        let A = a, B = b, C = c, D = d;

        // 64 rodadas
        for (let i = 0; i < 64; i++) {
            let F: number, g: number;
            
            if (i < 16) {
                F = (B & C) | (~B & D);
                g = i;
            } else if (i < 32) {
                F = (D & B) | (~D & C);
                g = (5 * i + 1) % 16;
            } else if (i < 48) {
                F = B ^ C ^ D;
                g = (3 * i + 5) % 16;
            } else {
                F = C ^ (B | ~D);
                g = (7 * i) % 16;
            }

            F = toUint32(F + A + K[i] + M[g]);
            A = D;
            D = C;
            C = B;
            B = toUint32(B + rotateLeft(F, shifts[i]));
        }

        a = toUint32(a + A);
        b = toUint32(b + B);
        c = toUint32(c + C);
        d = toUint32(d + D);
    }

    // Converte para hexadecimal (little-endian)
    const toHex = (n: number) => {
        let hex = '';
        for (let i = 0; i < 4; i++) {
            hex += ((n >>> (i * 8)) & 0xff).toString(16).padStart(2, '0');
        }
        return hex;
    };

    return toHex(a) + toHex(b) + toHex(c) + toHex(d);
}

/**
 * Gera um hash MD5 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash MD5 em formato hexadecimal
 */
export function md5(interpretador: any, texto: string): string {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHash('md5').update(texto).digest('hex');
    }
    
    // Implementação pura para navegadores
    return md5Pure(texto);
}

/**
 * Gera um hash SHA-1 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-1 em formato hexadecimal
 */
export async function sha1(interpretador: any, texto: string): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHash('sha1').update(texto).digest('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const buffer = stringToBuffer(texto);
        const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
        return bufferToHex(hashBuffer);
    }
    
    throw new Error('SHA-1 não disponível neste ambiente');
}

/**
 * Gera um hash SHA-256 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-256 em formato hexadecimal
 */
export async function sha256(interpretador: any, texto: string): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHash('sha256').update(texto).digest('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const buffer = stringToBuffer(texto);
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return bufferToHex(hashBuffer);
    }
    
    throw new Error('SHA-256 não disponível neste ambiente');
}

/**
 * Gera um hash SHA-512 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-512 em formato hexadecimal
 */
export async function sha512(interpretador: any, texto: string): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHash('sha512').update(texto).digest('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const buffer = stringToBuffer(texto);
        const hashBuffer = await crypto.subtle.digest('SHA-512', buffer);
        return bufferToHex(hashBuffer);
    }
    
    throw new Error('SHA-512 não disponível neste ambiente');
}

/**
 * Gera um HMAC (Hash-based Message Authentication Code) usando SHA-256.
 * @param texto O texto a ser autenticado
 * @param chave A chave secreta para geração do HMAC
 * @returns HMAC em formato hexadecimal
 */
export async function hmacSha256(interpretador: any, texto: string, chave: string): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHmac('sha256', chave).update(texto).digest('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const keyBuffer = stringToBuffer(chave);
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const textBuffer = stringToBuffer(texto);
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, textBuffer);
        return bufferToHex(signature);
    }
    
    throw new Error('HMAC-SHA256 não disponível neste ambiente');
}

/**
 * Gera um HMAC usando SHA-512.
 * @param texto O texto a ser autenticado
 * @param chave A chave secreta para geração do HMAC
 * @returns HMAC em formato hexadecimal
 */
export async function hmacSha512(interpretador: any, texto: string, chave: string): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.createHmac('sha512', chave).update(texto).digest('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const keyBuffer = stringToBuffer(chave);
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'HMAC', hash: 'SHA-512' },
            false,
            ['sign']
        );
        
        const textBuffer = stringToBuffer(texto);
        const signature = await crypto.subtle.sign('HMAC', cryptoKey, textBuffer);
        return bufferToHex(signature);
    }
    
    throw new Error('HMAC-SHA512 não disponível neste ambiente');
}

/**
 * Gera bytes aleatórios criptograficamente seguros.
 * @param tamanho Número de bytes a serem gerados
 * @returns Array de bytes aleatórios
 */
export function gerarBytesAleatorios(interpretador: any, tamanho: number): Uint8Array {
    if (isNode && nodeCrypto) {
        return new Uint8Array(nodeCrypto.randomBytes(tamanho));
    }
    
    if (isBrowser && crypto.getRandomValues) {
        const buffer = new Uint8Array(tamanho);
        crypto.getRandomValues(buffer);
        return buffer;
    }
    
    throw new Error('Geração de bytes aleatórios não disponível neste ambiente');
}

/**
 * Gera uma string aleatória em formato hexadecimal.
 * @param tamanho Número de bytes (o resultado terá o dobro de caracteres)
 * @returns String hexadecimal aleatória
 */
export function gerarStringAleatoria(interpretador: any, tamanho: number): string {
    const bytes = gerarBytesAleatorios(interpretador, tamanho);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Gera um UUID (Universally Unique Identifier) versão 4.
 * @returns UUID no formato padrão (ex: 'f47ac10b-58cc-4372-a567-0e02b2c3d479')
 */
export function gerarUuid(): string {
    if (isNode && nodeCrypto && nodeCrypto.randomUUID) {
        return nodeCrypto.randomUUID();
    }
    
    if (isBrowser && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    
    // Fallback: gera UUID v4 manualmente
    const bytes = gerarBytesAleatorios(null, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Versão 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variante RFC4122
    
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Codifica uma string em Base64.
 * @param texto Texto a ser codificado
 * @returns String em formato Base64
 */
export function codificarBase64(interpretador: any, texto: string): string {
    if (isNode) {
        return Buffer.from(texto, 'utf8').toString('base64');
    }
    
    if (isBrowser) {
        return btoa(unescape(encodeURIComponent(texto)));
    }
    
    throw new Error('Codificação Base64 não disponível neste ambiente');
}

/**
 * Decodifica uma string Base64.
 * @param textoBase64 String em formato Base64
 * @returns Texto decodificado
 */
export function decodificarBase64(interpretador: any, textoBase64: string): string {
    if (isNode) {
        return Buffer.from(textoBase64, 'base64').toString('utf8');
    }
    
    if (isBrowser) {
        return decodeURIComponent(escape(atob(textoBase64)));
    }
    
    throw new Error('Decodificação Base64 não disponível neste ambiente');
}

/**
 * Criptografa um texto usando AES-256-GCM (mais seguro que CBC).
 * @param texto Texto a ser criptografado
 * @param chave Chave de criptografia (deve ter 32 caracteres para AES-256)
 * @param vetorInicializacao Vetor de inicialização (IV) com 12 bytes. Se não fornecido, será gerado automaticamente.
 * @returns Objeto contendo o texto criptografado em Base64 e o IV usado
 */
export async function criptografarAes256(
    interpretador: any, 
    texto: string, 
    chave: string, 
    vetorInicializacao?: Uint8Array
): Promise<{ textoCriptografado: string; iv: string; authTag?: string }> {
    if (isNode && nodeCrypto) {
        const chaveBuffer = Buffer.alloc(32);
        chaveBuffer.write(chave.slice(0, 32));
        const iv = vetorInicializacao || nodeCrypto.randomBytes(12);
        
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', chaveBuffer, iv);
        let criptografado = cipher.update(texto, 'utf8', 'base64');
        criptografado += cipher.final('base64');
        const authTag = cipher.getAuthTag();
        
        return {
            textoCriptografado: criptografado,
            iv: Buffer.from(iv).toString('hex'),
            authTag: authTag.toString('hex')
        };
    }
    
    if (isBrowser && crypto.subtle) {
        const chaveBuffer = stringToBuffer(chave.slice(0, 32).padEnd(32, '0'));
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            chaveBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
        
        const iv = vetorInicializacao || crypto.getRandomValues(new Uint8Array(12));
        const textoBuffer = stringToBuffer(texto);
        const criptografado = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            textoBuffer
        );
        
        const criptografadoBase64 = btoa(String.fromCharCode(...new Uint8Array(criptografado)));
        return {
            textoCriptografado: criptografadoBase64,
            iv: bufferToHex(iv)
        };
    }
    
    throw new Error('Criptografia AES-256 não disponível neste ambiente');
}

/**
 * Descriptografa um texto usando AES-256-GCM.
 * @param textoCriptografado Texto criptografado em Base64
 * @param chave Chave de descriptografia (deve ter 32 caracteres)
 * @param iv Vetor de inicialização em formato hexadecimal
 * @param authTag Tag de autenticação em formato hexadecimal (Node.js apenas)
 * @returns Texto descriptografado
 */
export async function descriptografarAes256(
    interpretador: any, 
    textoCriptografado: string, 
    chave: string, 
    iv: string,
    authTag?: string
): Promise<string> {
    if (isNode && nodeCrypto) {
        const chaveBuffer = Buffer.alloc(32);
        chaveBuffer.write(chave.slice(0, 32));
        const ivBuffer = Buffer.from(iv, 'hex');
        
        // Se authTag não foi fornecido, assume que está concatenado no textoCriptografado
        let dados: Buffer;
        let tag: Buffer;
        
        if (authTag) {
            dados = Buffer.from(textoCriptografado, 'base64');
            tag = Buffer.from(authTag, 'hex');
        } else {
            // Tenta separar dados e tag (último elemento após split pode ser authTag)
            dados = Buffer.from(textoCriptografado, 'base64');
            tag = Buffer.alloc(16); // Tag vazia, não será usada neste caso
        }
        
        const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', chaveBuffer, ivBuffer);
        if (authTag) {
            decipher.setAuthTag(tag);
        }
        
        let descriptografado = decipher.update(dados, undefined, 'utf8');
        descriptografado += decipher.final('utf8');
        
        return descriptografado;
    }
    
    if (isBrowser && crypto.subtle) {
        const chaveBuffer = stringToBuffer(chave.slice(0, 32).padEnd(32, '0'));
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            chaveBuffer,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        const ivBuffer = new Uint8Array(iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
        const criptografadoBuffer = Uint8Array.from(atob(textoCriptografado), c => c.charCodeAt(0));
        
        const descriptografado = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer },
            cryptoKey,
            criptografadoBuffer.buffer
        );
        
        return bufferToString(descriptografado);
    }
    
    throw new Error('Descriptografia AES-256 não disponível neste ambiente');
}

/**
 * Gera um par de chaves RSA (pública e privada).
 * @param tamanhoModulo Tamanho do módulo em bits (padrão: 2048)
 * @returns Objeto contendo as chaves pública e privada
 */
export async function gerarParChavesRsa(interpretador: any, tamanhoModulo: number = 2048): Promise<{
    chavePublica: any;
    chavePrivada: any;
}> {
    if (isNode && nodeCrypto) {
        const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
            modulusLength: tamanhoModulo,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        return { chavePublica: publicKey, chavePrivada: privateKey };
    }
    
    if (isBrowser && crypto.subtle) {
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: tamanhoModulo,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );
        
        return { chavePublica: keyPair.publicKey, chavePrivada: keyPair.privateKey };
    }
    
    throw new Error('Geração de chaves RSA não disponível neste ambiente');
}

/**
 * Criptografa um texto usando uma chave pública RSA.
 * @param texto Texto a ser criptografado
 * @param chavePublica Chave pública RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns Texto criptografado em Base64
 */
export async function criptografarRsa(interpretador: any, texto: string, chavePublica: any): Promise<string> {
    if (isNode && nodeCrypto && typeof chavePublica === 'string') {
        const buffer = Buffer.from(texto, 'utf8');
        const criptografado = nodeCrypto.publicEncrypt(chavePublica, buffer);
        return criptografado.toString('base64');
    }
    
    if (isBrowser && crypto.subtle) {
        const textoBuffer = stringToBuffer(texto);
        const criptografado = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            chavePublica,
            textoBuffer
        );
        return btoa(String.fromCharCode(...new Uint8Array(criptografado)));
    }
    
    throw new Error('Criptografia RSA não disponível neste ambiente');
}

/**
 * Descriptografa um texto usando uma chave privada RSA.
 * @param textoCriptografado Texto criptografado em Base64
 * @param chavePrivada Chave privada RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns Texto descriptografado
 */
export async function descriptografarRsa(interpretador: any, textoCriptografado: string, chavePrivada: any): Promise<string> {
    if (isNode && nodeCrypto && typeof chavePrivada === 'string') {
        const buffer = Buffer.from(textoCriptografado, 'base64');
        const descriptografado = nodeCrypto.privateDecrypt(chavePrivada, buffer);
        return descriptografado.toString('utf8');
    }
    
    if (isBrowser && crypto.subtle) {
        const criptografadoBuffer = Uint8Array.from(atob(textoCriptografado), c => c.charCodeAt(0));
        const descriptografado = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            chavePrivada,
            criptografadoBuffer.buffer
        );
        return bufferToString(descriptografado);
    }
    
    throw new Error('Descriptografia RSA não disponível neste ambiente');
}

/**
 * Assina digitalmente um texto usando uma chave privada RSA.
 * @param texto Texto a ser assinado
 * @param chavePrivada Chave privada RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns Assinatura digital em Base64
 */
export async function assinarRsa(interpretador: any, texto: string, chavePrivada: any): Promise<string> {
    if (isNode && nodeCrypto && typeof chavePrivada === 'string') {
        const sign = nodeCrypto.createSign('SHA256');
        sign.update(texto);
        sign.end();
        return sign.sign(chavePrivada, 'base64');
    }
    
    if (isBrowser && crypto.subtle) {
        // Para assinatura em navegadores, precisa gerar chaves com o algoritmo correto
        const textoBuffer = stringToBuffer(texto);
        const assinatura = await crypto.subtle.sign(
            { name: 'RSA-PSS', saltLength: 32 },
            chavePrivada,
            textoBuffer
        );
        return btoa(String.fromCharCode(...new Uint8Array(assinatura)));
    }
    
    throw new Error('Assinatura RSA não disponível neste ambiente');
}

/**
 * Verifica uma assinatura digital usando uma chave pública RSA.
 * @param texto Texto original
 * @param assinatura Assinatura digital em Base64
 * @param chavePublica Chave pública RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns true se a assinatura for válida, false caso contrário
 */
export async function verificarAssinaturaRsa(
    interpretador: any, 
    texto: string, 
    assinatura: string, 
    chavePublica: any
): Promise<boolean> {
    if (isNode && nodeCrypto && typeof chavePublica === 'string') {
        const verify = nodeCrypto.createVerify('SHA256');
        verify.update(texto);
        verify.end();
        return verify.verify(chavePublica, assinatura, 'base64');
    }
    
    if (isBrowser && crypto.subtle) {
        const textoBuffer = stringToBuffer(texto);
        const assinaturaBuffer = Uint8Array.from(atob(assinatura), c => c.charCodeAt(0));
        
        try {
            return await crypto.subtle.verify(
                { name: 'RSA-PSS', saltLength: 32 },
                chavePublica,
                assinaturaBuffer.buffer,
                textoBuffer
            );
        } catch {
            return false;
        }
    }
    
    throw new Error('Verificação de assinatura RSA não disponível neste ambiente');
}

/**
 * Gera um salt aleatório para uso em derivação de chaves.
 * @param tamanho Tamanho do salt em bytes (padrão: 16)
 * @returns Salt em formato hexadecimal
 */
export function gerarSalt(interpretador?: any, tamanho: number = 16): string {
    return gerarStringAleatoria(interpretador, tamanho);
}

/**
 * Deriva uma chave a partir de uma senha usando PBKDF2.
 * @param senha Senha base
 * @param sal Salt (valor aleatório para aumentar segurança)
 * @param iteracoes Número de iterações (padrão: 100000)
 * @param tamanhoChave Tamanho da chave derivada em bytes (padrão: 32)
 * @returns Chave derivada em formato hexadecimal
 */
export async function derivarChavePbkdf2(
    interpretador: any, 
    senha: string,
    sal: string,
    iteracoes: number = 100000,
    tamanhoChave: number = 32
): Promise<string> {
    if (isNode && nodeCrypto) {
        return nodeCrypto.pbkdf2Sync(senha, sal, iteracoes, tamanhoChave, 'sha256').toString('hex');
    }
    
    if (isBrowser && crypto.subtle) {
        const senhaBuffer = stringToBuffer(senha);
        const salBuffer = stringToBuffer(sal);
        
        const baseKey = await crypto.subtle.importKey(
            'raw',
            senhaBuffer,
            'PBKDF2',
            false,
            ['deriveBits']
        );
        
        const derivedBits = await crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: salBuffer,
                iterations: iteracoes,
                hash: 'SHA-256'
            },
            baseKey,
            tamanhoChave * 8
        );
        
        return bufferToHex(derivedBits);
    }
    
    throw new Error('PBKDF2 não disponível neste ambiente');
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