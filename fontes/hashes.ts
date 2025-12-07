import { bufferToHex, nodeCrypto, noNavegador, noNode, stringToBuffer } from "./comum";

/**
 * Implementação pura de MD5 em TypeScript
 */
function md5Puro(texto: string): string {
    // Converte string para bytes UTF-8
    const utf8Bytes: number[] = [];
    for (let i = 0; i < texto.length; i++) {
        let charCode = texto.charCodeAt(i);
        if (charCode < 0x80) {
            utf8Bytes.push(charCode);
        } else if (charCode < 0x800) {
            utf8Bytes.push(0xc0 | (charCode >> 6), 0x80 | (charCode & 0x3f));
        } else if (charCode < 0xd800 || charCode >= 0xe000) {
            utf8Bytes.push(0xe0 | (charCode >> 12), 0x80 | ((charCode >> 6) & 0x3f), 0x80 | (charCode & 0x3f));
        } else {
            i++;
            charCode = 0x10000 + (((charCode & 0x3ff) << 10) | (texto.charCodeAt(i) & 0x3ff));
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
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHash('md5').update(texto).digest('hex');
    }
    
    // Implementação pura para navegadores
    return md5Puro(texto);
}

/**
 * Gera um hash SHA-1 de uma string.
 * @param texto O texto a ser transformado em hash
 * @returns Hash SHA-1 em formato hexadecimal
 */
export async function sha1(interpretador: any, texto: string): Promise<string> {
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHash('sha1').update(texto).digest('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHash('sha256').update(texto).digest('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHash('sha512').update(texto).digest('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHmac('sha256', chave).update(texto).digest('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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
    if (noNode && nodeCrypto) {
        return nodeCrypto.createHmac('sha512', chave).update(texto).digest('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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