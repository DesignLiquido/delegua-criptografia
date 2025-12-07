import { bufferToHex, nodeCrypto, noNavegador, noNode, stringToBuffer } from "./comum";

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
    if (!iteracoes) {
        iteracoes = 100000
    }

    if (!tamanhoChave) {
        tamanhoChave = 32
    }

    if (noNode && nodeCrypto) {
        return nodeCrypto.pbkdf2Sync(senha, sal, iteracoes, tamanhoChave, 'sha256').toString('hex');
    }
    
    if (noNavegador && crypto.subtle) {
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