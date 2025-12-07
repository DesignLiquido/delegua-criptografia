import { noNode, nodeCrypto, noNavegador, stringToBuffer, bufferToString } from "./comum";

/**
 * Gera um par de chaves RSA (pública e privada).
 * No Node.js, retorna strings PEM. No navegador, retorna CryptoKey objects.
 * @param tamanhoModulo Tamanho do módulo em bits (padrão: 2048)
 * @returns Objeto contendo as chaves pública e privada
 */
export async function gerarParChavesRsa(interpretador: any, tamanhoModulo: number = 2048): Promise<{
    chavePublica: any;
    chavePrivada: any;
}> {
    if (noNode && nodeCrypto) {
        const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
            modulusLength: tamanhoModulo,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        return { chavePublica: publicKey, chavePrivada: privateKey };
    }
    
    if (noNavegador && crypto.subtle) {
        // Para navegadores, geramos chaves RSA-OAEP para criptografia
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
 * Gera um par de chaves RSA para assinatura digital.
 * No Node.js, retorna strings PEM. No navegador, retorna CryptoKey objects.
 * @param tamanhoModulo Tamanho do módulo em bits (padrão: 2048)
 * @returns Objeto contendo as chaves pública e privada para assinatura
 */
export async function gerarParChavesRsaAssinatura(interpretador: any, tamanhoModulo: number = 2048): Promise<{
    chavePublica: any;
    chavePrivada: any;
}> {
    if (noNode && nodeCrypto) {
        const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync('rsa', {
            modulusLength: tamanhoModulo,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        return { chavePublica: publicKey, chavePrivada: privateKey };
    }
    
    if (noNavegador && crypto.subtle) {
        // Para navegadores, geramos chaves RSA-PSS para assinatura
        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-PSS',
                modulusLength: tamanhoModulo,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['sign', 'verify']
        );
        
        return { chavePublica: keyPair.publicKey, chavePrivada: keyPair.privateKey };
    }
    
    throw new Error('Geração de chaves RSA para assinatura não disponível neste ambiente');
}

/**
 * Criptografa um texto usando uma chave pública RSA.
 * @param texto Texto a ser criptografado
 * @param chavePublica Chave pública RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns Texto criptografado em Base64
 */
export async function criptografarRsa(interpretador: any, texto: string, chavePublica: any): Promise<string> {
    if (noNode && nodeCrypto && typeof chavePublica === 'string') {
        const buffer = Buffer.from(texto, 'utf8');
        const criptografado = nodeCrypto.publicEncrypt(chavePublica, buffer);
        return criptografado.toString('base64');
    }
    
    if (noNavegador && crypto.subtle) {
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
export async function descriptografarRsa(interpretador: { resolverValor: (valor: any) => any }, textoCriptografado: any, chavePrivada: any): Promise<string> {
    const chavePrivadaResolvida = interpretador.resolverValor(chavePrivada);
    const textoCriptografadoResolvido = interpretador.resolverValor(textoCriptografado);

    if (noNode && nodeCrypto) {
        const buffer = Buffer.from(textoCriptografadoResolvido, 'base64');
        const descriptografado = nodeCrypto.privateDecrypt(chavePrivadaResolvida, buffer);
        return descriptografado.toString('utf8');
    }
    
    if (noNavegador && crypto.subtle) {
        const criptografadoBuffer = Uint8Array.from(atob(textoCriptografadoResolvido), c => c.charCodeAt(0));
        const descriptografado = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            chavePrivadaResolvida,
            criptografadoBuffer.buffer
        );
        return bufferToString(descriptografado);
    }
    
    throw new Error('Descriptografia RSA não disponível neste ambiente');
}

/**
 * Assina digitalmente um texto usando uma chave privada RSA.
 * IMPORTANTE: Para navegadores, use chaves geradas com gerarParChavesRsaAssinatura()
 * @param texto Texto a ser assinado
 * @param chavePrivada Chave privada RSA em formato PEM (Node.js) ou CryptoKey (Browser)
 * @returns Assinatura digital em Base64
 */
export async function assinarRsa(interpretador: any, texto: string, chavePrivada: any): Promise<string> {
    if (noNode && nodeCrypto && typeof chavePrivada === 'string') {
        const sign = nodeCrypto.createSign('SHA256');
        sign.update(texto);
        sign.end();
        return sign.sign(chavePrivada, 'base64');
    }
    
    if (noNavegador && crypto.subtle) {
        // Verifica se a chave é do tipo correto (RSA-PSS)
        if (chavePrivada.algorithm && chavePrivada.algorithm.name !== 'RSA-PSS') {
            throw new Error('Para assinatura em navegadores, use chaves geradas com gerarParChavesRsaAssinatura()');
        }
        
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
 * IMPORTANTE: Para navegadores, use chaves geradas com gerarParChavesRsaAssinatura()
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
    if (noNode && nodeCrypto && typeof chavePublica === 'string') {
        const verify = nodeCrypto.createVerify('SHA256');
        verify.update(texto);
        verify.end();
        return verify.verify(chavePublica, assinatura, 'base64');
    }
    
    if (noNavegador && crypto.subtle) {
        // Verifica se a chave é do tipo correto (RSA-PSS)
        if (chavePublica.algorithm && chavePublica.algorithm.name !== 'RSA-PSS') {
            throw new Error('Para verificação em navegadores, use chaves geradas com gerarParChavesRsaAssinatura()');
        }
        
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