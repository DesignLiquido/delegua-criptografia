import { noNode, noNavegador } from "./comum";

/**
 * Codifica uma string em Base64.
 * @param texto Texto a ser codificado
 * @returns String em formato Base64
 */
export function codificarBase64(interpretador: any, texto: string): string {
    if (noNode) {
        return Buffer.from(texto, 'utf8').toString('base64');
    }
    
    if (noNavegador) {
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
    if (noNode) {
        return Buffer.from(textoBase64, 'base64').toString('utf8');
    }
    
    if (noNavegador) {
        return decodeURIComponent(escape(atob(textoBase64)));
    }
    
    throw new Error('Decodificação Base64 não disponível neste ambiente');
}
