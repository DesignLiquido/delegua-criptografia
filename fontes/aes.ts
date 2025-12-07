import { noNode, nodeCrypto, noNavegador, stringToBuffer, bufferToHex, bufferToString } from "./comum";

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
): Promise<{ textoCriptografado: string; iv: string }> {
    if (noNode && nodeCrypto) {
        const chaveBuffer = Buffer.alloc(32);
        chaveBuffer.write(chave.slice(0, 32));
        const iv = vetorInicializacao || nodeCrypto.randomBytes(12);
        
        const cipher = nodeCrypto.createCipheriv('aes-256-gcm', chaveBuffer, iv);
        let encrypted = cipher.update(texto, 'utf8');
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const authTag = cipher.getAuthTag();
        
        // Combina dados criptografados + authTag (igual aos navegadores)
        const combined = Buffer.concat([encrypted, authTag]);
        
        return {
            textoCriptografado: combined.toString('base64'),
            iv: Buffer.from(iv).toString('hex')
        };
    }
    
    if (noNavegador && crypto.subtle) {
        const chaveBuffer = stringToBuffer(chave.slice(0, 32).padEnd(32, '0'));
        const cryptoKey = await crypto.subtle.importKey(
            'raw', chaveBuffer, { name: 'AES-GCM' }, false, ['encrypt']
        );
        
        const iv = vetorInicializacao || crypto.getRandomValues(new Uint8Array(12));
        const textoBuffer = stringToBuffer(texto);
        const criptografado = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv }, cryptoKey, textoBuffer
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
 * @returns Texto descriptografado
 */
export async function descriptografarAes256(
    interpretador: { resolverValor: (valor: any) => any }, 
    textoCriptografado: string, 
    chave: string, 
    iv: string
): Promise<string> {
    const textoCriptografadoResolvido = interpretador.resolverValor(textoCriptografado);
    const chaveResolvida = interpretador.resolverValor(chave);
    const ivResolvido: string = interpretador.resolverValor(iv);

    if (noNode && nodeCrypto) {
        const chaveBuffer = Buffer.alloc(32);
        chaveBuffer.write(chaveResolvida.slice(0, 32));
        const ivBuffer = Buffer.from(ivResolvido, 'hex');
        
        // O textoCriptografado contém: dados + authTag (últimos 16 bytes)
        const combined = Buffer.from(textoCriptografadoResolvido, 'base64');
        const authTagLength = 16;
        const dados = combined.slice(0, combined.length - authTagLength);
        const authTag = combined.slice(combined.length - authTagLength);
        
        const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', chaveBuffer, ivBuffer);
        decipher.setAuthTag(authTag);
        
        let descriptografado = decipher.update(dados, undefined, 'utf8');
        descriptografado += decipher.final('utf8');
        
        return descriptografado;
    }
    
    if (noNavegador && crypto.subtle) {
        const chaveBuffer = stringToBuffer(chaveResolvida.slice(0, 32).padEnd(32, '0'));
        const cryptoKey = await crypto.subtle.importKey(
            'raw', chaveBuffer, { name: 'AES-GCM' }, false, ['decrypt']
        );
        
        const ivBuffer = new Uint8Array(ivResolvido.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
        const criptografadoBuffer = Uint8Array.from(atob(textoCriptografadoResolvido), c => c.charCodeAt(0));
        
        const descriptografado = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: ivBuffer }, cryptoKey, criptografadoBuffer.buffer
        );
        
        return bufferToString(descriptografado);
    }
    
    throw new Error('Descriptografia AES-256 não disponível neste ambiente');
}