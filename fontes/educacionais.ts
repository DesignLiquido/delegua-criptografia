import { bufferToString, stringToBuffer } from "./comum";

/**
 * Cifra XOR - Criptografia simétrica simples usando operação XOR bit a bit.
 * ATENÇÃO: Apenas para fins educacionais, NÃO é segura para dados sensíveis!
 * @param texto Texto a ser cifrado/decifrado
 * @param chave Chave para a operação XOR (pode ser qualquer tamanho)
 * @returns Texto cifrado/decifrado em formato hexadecimal
 */
export function cifrarXor(interpretador: any, texto: string, chave: string): string {
    if (!chave || chave.length === 0) {
        throw new Error('A chave não pode estar vazia');
    }
    
    const textoBytes = stringToBuffer(texto);
    const chaveBytes = stringToBuffer(chave);
    const resultado: number[] = [];
    
    for (let i = 0; i < textoBytes.length; i++) {
        // XOR com a chave (repetindo a chave se necessário)
        const xor = textoBytes[i] ^ chaveBytes[i % chaveBytes.length];
        resultado.push(xor);
    }
    
    // Retorna em hexadecimal para facilitar visualização
    return resultado.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Decifra XOR - Decifra texto que foi cifrado com XOR.
 * Como XOR é simétrico, a operação é idêntica à cifragem.
 * @param textoHex Texto cifrado em formato hexadecimal
 * @param chave Chave usada na cifragem
 * @returns Texto original
 */
export function decifrarXor(interpretador: any, textoHex: string, chave: string): string {
    if (!chave || chave.length === 0) {
        throw new Error('A chave não pode estar vazia');
    }
    
    // Converte hexadecimal para bytes
    const textoBytes: number[] = [];
    for (let i = 0; i < textoHex.length; i += 2) {
        textoBytes.push(parseInt(textoHex.substr(i, 2), 16));
    }
    
    const chaveBytes = stringToBuffer(chave);
    const resultado: number[] = [];
    
    for (let i = 0; i < textoBytes.length; i++) {
        // XOR com a chave (operação simétrica)
        const xor = textoBytes[i] ^ chaveBytes[i % chaveBytes.length];
        resultado.push(xor);
    }
    
    // Converte bytes de volta para string
    return bufferToString(new Uint8Array(resultado));
}

/**
 * ROT13 - Cifra de substituição simples que desloca letras em 13 posições.
 * Apenas para fins educacionais, NÃO é segura!
 * Como ROT13 desloca 13 posições no alfabeto de 26 letras, aplicar duas vezes
 * retorna o texto original (é sua própria inversa).
 * @param texto Texto a ser cifrado/decifrado
 * @returns Texto com ROT13 aplicado
 */
export function rot13(interpretador: any, texto: string): string {
    return texto.replace(/[a-zA-Z]/g, (char) => {
        const codigo = char.charCodeAt(0);
        
        // Letras maiúsculas (A-Z: 65-90)
        if (codigo >= 65 && codigo <= 90) {
            return String.fromCharCode(((codigo - 65 + 13) % 26) + 65);
        }
        
        // Letras minúsculas (a-z: 97-122)
        if (codigo >= 97 && codigo <= 122) {
            return String.fromCharCode(((codigo - 97 + 13) % 26) + 97);
        }
        
        return char;
    });
}

/**
 * ROT-N - Generalização do ROT13 que permite deslocamento customizado.
 * Cifra de César com deslocamento configurável.
 * ATENÇÃO: Apenas para fins educacionais!
 * @param texto Texto a ser cifrado
 * @param deslocamento Número de posições para deslocar (padrão: 13)
 * @returns Texto cifrado
 */
export function rotN(interpretador: any, texto: string, deslocamento: number = 13): string {
    // Normaliza o deslocamento para estar entre 0-25
    deslocamento = ((deslocamento % 26) + 26) % 26;
    
    return texto.replace(/[a-zA-Z]/g, (char) => {
        const codigo = char.charCodeAt(0);
        
        // Letras maiúsculas (A-Z: 65-90)
        if (codigo >= 65 && codigo <= 90) {
            return String.fromCharCode(((codigo - 65 + deslocamento) % 26) + 65);
        }
        
        // Letras minúsculas (a-z: 97-122)
        if (codigo >= 97 && codigo <= 122) {
            return String.fromCharCode(((codigo - 97 + deslocamento) % 26) + 97);
        }
        
        return char;
    });
}

/**
 * Decifra ROT-N - Decifra texto cifrado com ROT-N.
 * @param texto Texto cifrado
 * @param deslocamento Deslocamento usado na cifragem
 * @returns Texto original
 */
export function decifrarRotN(interpretador: any, texto: string, deslocamento: number = 13): string {
    // Para decifrar, basta aplicar o deslocamento negativo
    return rotN(interpretador, texto, -deslocamento);
}