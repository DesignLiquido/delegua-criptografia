import { noNode, noNavegador, nodeCrypto } from "./comum";

/**
 * Gera bytes aleatórios criptograficamente seguros.
 * @param tamanho Número de bytes a serem gerados
 * @returns Array de bytes aleatórios
 */
export function gerarBytesAleatorios(interpretador: any, tamanho: number): Uint8Array {
    if (noNode && nodeCrypto) {
        return new Uint8Array(nodeCrypto.randomBytes(tamanho));
    }
    
    if (noNavegador && crypto.getRandomValues) {
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
export function gerarTextoAleatorio(interpretador: any, tamanho: number): string {
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
    if (noNode && nodeCrypto && nodeCrypto.randomUUID) {
        return nodeCrypto.randomUUID();
    }
    
    if (noNavegador && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    
    // Fallback: gera UUID v4 manualmente
    const bytes = gerarBytesAleatorios(null, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Versão 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variante RFC4122
    
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}