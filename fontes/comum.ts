// Detecta o ambiente
const noNode = typeof process !== 'undefined' && process.versions != null && process.versions.node != null;
const noNavegador = typeof globalThis !== 'undefined' && typeof (globalThis as any).window !== 'undefined';

// Importa crypto do Node.js apenas se estiver em ambiente Node
let nodeCrypto: any = null;
if (noNode) {
    nodeCrypto = require('crypto');
}

/**
 * Converte ArrayBuffer para string hexadecimal
 */
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Converte string para ArrayBuffer
 */
export function stringToBuffer(str: string): Uint8Array {
    const encoder = new TextEncoder();
    return encoder.encode(str);
}

/**
 * Converte ArrayBuffer para string
 */
export function bufferToString(buffer: ArrayBuffer | Uint8Array): string {
    const decoder = new TextDecoder();
    return decoder.decode(buffer);
}

export { noNode, noNavegador, nodeCrypto };