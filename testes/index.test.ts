import { md5, sha1, sha256, sha512, hmacSha256, hmacSha512 } from '../fontes/hashes';
import { gerarBytesAleatorios, gerarTextoAleatorio, gerarUuid } from '../fontes/aleatorios';
import { codificarBase64, decodificarBase64 } from '../fontes/base64';
import { criptografarAes256, descriptografarAes256 } from '../fontes/aes';
import { gerarParChavesRsa, gerarParChavesRsaAssinatura, criptografarRsa, descriptografarRsa, assinarRsa, verificarAssinaturaRsa } from '../fontes/rsa';
import { derivarChavePbkdf2 } from '../fontes/pbkdf2';
import { gerarSalt } from '../fontes/salt';
import { cifrarXor, decifrarXor, rot13, rotN, decifrarRotN } from '../fontes/educacionais';

const interpretadorDeMentirinha = {
    resolverValor: (valor: any) => valor
}

describe('Funções de Hash', () => {
    const texto = 'Olá Mundo';

    it('md5 deve gerar hash correto', () => {
        const hash = md5(undefined, texto);
        expect(hash).toHaveLength(32);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha1 deve gerar hash correto', async () => {
        const hash = await sha1(undefined, texto);
        expect(hash).toHaveLength(40);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha256 deve gerar hash correto', async () => {
        const hash = await sha256(undefined, texto);
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha512 deve gerar hash correto', async () => {
        const hash = await sha512(undefined, texto);
        expect(hash).toHaveLength(128);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('hashes devem ser consistentes', async () => {
        const hash1 = await sha256(undefined, texto);
        const hash2 = await sha256(undefined, texto);
        expect(hash1).toBe(hash2);
    });
});

describe('Funções HMAC', () => {
    const texto = 'mensagem';
    const chave = 'chave-secreta';

    it('hmacSha256 deve gerar HMAC correto', async () => {
        const hmac = await hmacSha256(undefined, texto, chave);
        expect(hmac).toHaveLength(64);
        expect(hmac).toMatch(/^[a-f0-9]+$/);
    });

    it('hmacSha512 deve gerar HMAC correto', async () => {
        const hmac = await hmacSha512(undefined, texto, chave);
        expect(hmac).toHaveLength(128);
        expect(hmac).toMatch(/^[a-f0-9]+$/);
    });

    it('HMACs devem ser consistentes com mesma chave', async () => {
        const hmac1 = await hmacSha256(undefined, texto, chave);
        const hmac2 = await hmacSha256(undefined, texto, chave);
        expect(hmac1).toBe(hmac2);
    });

    it('HMACs devem ser diferentes com chaves diferentes', async () => {
        const hmac1 = await hmacSha256(undefined, texto, chave);
        const hmac2 = await hmacSha256(undefined, texto, 'outra-chave');
        expect(hmac1).not.toBe(hmac2);
    });
});

describe('Geração de Dados Aleatórios', () => {
    it('gerarBytesAleatorios deve gerar buffer do tamanho correto', () => {
        const bytes = gerarBytesAleatorios(undefined, 16);
        expect(bytes).toBeInstanceOf(Uint8Array);
        expect(bytes.length).toBe(16);
    });

    it('gerarTextoAleatorio deve gerar texto do tamanho correto', () => {
        const str = gerarTextoAleatorio(undefined, 16);
        expect(str).toHaveLength(32); // 16 bytes = 32 caracteres hex
        expect(str).toMatch(/^[a-f0-9]+$/);
    });

    it('gerarTextoAleatorio deve gerar valores diferentes', () => {
        const str1 = gerarTextoAleatorio(undefined, 16);
        const str2 = gerarTextoAleatorio(undefined, 16);
        expect(str1).not.toBe(str2);
    });

    it('gerarUuid deve gerar UUID válido', () => {
        const uuid = gerarUuid();
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        expect(uuid).toMatch(uuidRegex);
    });

    it('gerarSalt deve gerar salt do tamanho correto', () => {
        const sal = gerarSalt(undefined, 16);
        expect(sal).toHaveLength(32); // 16 bytes = 32 caracteres hex
        expect(sal).toMatch(/^[a-f0-9]+$/);
    });
});

describe('Codificação Base64', () => {
    const texto = 'Texto para codificar';

    it('codificarBase64 deve codificar corretamente', () => {
        const codificado = codificarBase64(undefined, texto);
        expect(codificado).toBeTruthy();
        expect(typeof codificado).toBe('string');
    });

    it('decodificarBase64 deve decodificar corretamente', () => {
        const codificado = codificarBase64(undefined, texto);
        const decodificado = decodificarBase64(undefined, codificado);
        expect(decodificado).toBe(texto);
    });

    it('ciclo completo de codificação/decodificação', () => {
        const textos = ['Olá', 'Hello World!', '测试', 'Teste 123 !@#'];
        textos.forEach(t => {
            const codificado = codificarBase64(undefined, t);
            const decodificado = decodificarBase64(undefined, codificado);
            expect(decodificado).toBe(t);
        });
    });
});

describe('Criptografia AES-256', () => {
    const texto = 'Mensagem secreta';
    const chave = 'minha-chave-super-secreta-aqui!'; // 32 caracteres

    it('criptografarAes256 deve retornar objeto com campos corretos', async () => {
        const resultado = await criptografarAes256(undefined, texto, chave);
        expect(resultado).toHaveProperty('textoCriptografado');
        expect(resultado).toHaveProperty('iv');
        expect(typeof resultado.textoCriptografado).toBe('string');
        expect(typeof resultado.iv).toBe('string');
        // authTag não deve estar no retorno - está embutido no textoCriptografado
        expect(resultado).not.toHaveProperty('authTag');
    });

    it('descriptografarAes256 deve recuperar texto original', async () => {
        const resultado = await criptografarAes256(undefined, texto, chave);
        const descriptografado = await descriptografarAes256(
            interpretadorDeMentirinha, 
            resultado.textoCriptografado,
            chave,
            resultado.iv
        );
        expect(descriptografado).toBe(texto);
    });

    it('textos diferentes devem gerar criptografias diferentes', async () => {
        const resultado1 = await criptografarAes256(undefined, 'texto1', chave);
        const resultado2 = await criptografarAes256(undefined, 'texto2', chave);
        expect(resultado1.textoCriptografado).not.toBe(resultado2.textoCriptografado);
    });

    it('mesmo texto deve gerar IVs diferentes em criptografias diferentes', async () => {
        const resultado1 = await criptografarAes256(undefined, texto, chave);
        const resultado2 = await criptografarAes256(undefined, texto, chave);
        expect(resultado1.iv).not.toBe(resultado2.iv);
        expect(resultado1.textoCriptografado).not.toBe(resultado2.textoCriptografado);
    });

    it('API unificada - mesmo contrato em Node.js e navegador', async () => {
        // Este teste verifica que não precisamos passar authTag separadamente
        const resultado = await criptografarAes256(undefined, texto, chave);
        
        // Deve funcionar sem passar authTag (API unificada)
        const descriptografado = await descriptografarAes256(
            interpretadorDeMentirinha,
            resultado.textoCriptografado,
            chave,
            resultado.iv
            // Sem authTag - igual em ambos os ambientes!
        );
        
        expect(descriptografado).toBe(texto);
    });
});

describe('Criptografia RSA (RSA-OAEP)', () => {
    let chavePublica: any;
    let chavePrivada: any;

    beforeAll(async () => {
        const par = await gerarParChavesRsa(undefined, 2048);
        chavePublica = par.chavePublica;
        chavePrivada = par.chavePrivada;
    });

    it('gerarParChavesRsa deve gerar par de chaves válido', async () => {
        const par = await gerarParChavesRsa(undefined, 2048);
        if (typeof par.chavePublica === 'string') {
            expect(par.chavePublica).toContain('BEGIN PUBLIC KEY');
            expect(par.chavePublica).toContain('END PUBLIC KEY');
            expect(par.chavePrivada).toContain('BEGIN PRIVATE KEY');
            expect(par.chavePrivada).toContain('END PRIVATE KEY');
        } else {
            expect(par.chavePublica).toBeTruthy();
            expect(par.chavePrivada).toBeTruthy();
            expect(par.chavePublica.algorithm.name).toBe('RSA-OAEP');
            expect(par.chavePrivada.algorithm.name).toBe('RSA-OAEP');
        }
    });

    it('criptografarRsa deve criptografar texto', async () => {
        const texto = 'Mensagem confidencial';
        const criptografado = await criptografarRsa(undefined, texto, chavePublica);
        expect(criptografado).toBeTruthy();
        expect(typeof criptografado).toBe('string');
        expect(criptografado).not.toBe(texto);
    });

    it('descriptografarRsa deve recuperar texto original', async () => {
        const texto = 'Mensagem confidencial';
        const criptografado = await criptografarRsa(undefined, texto, chavePublica);
        const descriptografado = await descriptografarRsa(interpretadorDeMentirinha, criptografado, chavePrivada);
        expect(descriptografado).toBe(texto);
    });

    it('ciclo completo de criptografia/descriptografia RSA', async () => {
        const textos = ['Olá', 'Teste 123', 'Dados sensíveis'];
        for (const texto of textos) {
            const criptografado = await criptografarRsa(undefined, texto, chavePublica);
            const descriptografado = await descriptografarRsa(interpretadorDeMentirinha, criptografado, chavePrivada);
            expect(descriptografado).toBe(texto);
        }
    });
});

describe('Assinatura Digital RSA (RSA-PSS)', () => {
    let chavePublica: any;
    let chavePrivada: any;

    beforeAll(async () => {
        const par = await gerarParChavesRsaAssinatura(undefined, 2048);
        chavePublica = par.chavePublica;
        chavePrivada = par.chavePrivada;
    });

    it('gerarParChavesRsaAssinatura deve gerar par de chaves válido', async () => {
        const par = await gerarParChavesRsaAssinatura(undefined, 2048);
        if (typeof par.chavePublica === 'string') {
            expect(par.chavePublica).toContain('BEGIN PUBLIC KEY');
            expect(par.chavePublica).toContain('END PUBLIC KEY');
            expect(par.chavePrivada).toContain('BEGIN PRIVATE KEY');
            expect(par.chavePrivada).toContain('END PRIVATE KEY');
        } else {
            expect(par.chavePublica).toBeTruthy();
            expect(par.chavePrivada).toBeTruthy();
            expect(par.chavePublica.algorithm.name).toBe('RSA-PSS');
            expect(par.chavePrivada.algorithm.name).toBe('RSA-PSS');
        }
    });

    it('assinarRsa deve gerar assinatura', async () => {
        const texto = 'Documento importante';
        const assinatura = await assinarRsa(undefined, texto, chavePrivada);
        expect(assinatura).toBeTruthy();
        expect(typeof assinatura).toBe('string');
    });

    it('verificarAssinaturaRsa deve validar assinatura correta', async () => {
        const texto = 'Documento importante';
        const assinatura = await assinarRsa(undefined, texto, chavePrivada);
        const valida = await verificarAssinaturaRsa(undefined, texto, assinatura, chavePublica);
        expect(valida).toBe(true);
    });

    it('verificarAssinaturaRsa deve rejeitar assinatura inválida', async () => {
        const texto = 'Documento importante';
        const assinatura = await assinarRsa(undefined, texto, chavePrivada);
        const textoAlterado = 'Documento importante modificado';
        const valida = await verificarAssinaturaRsa(undefined, textoAlterado, assinatura, chavePublica);
        expect(valida).toBe(false);
    });

    it('verificarAssinaturaRsa deve rejeitar assinatura adulterada', async () => {
        const texto = 'Documento importante';
        const assinatura = await assinarRsa(undefined, texto, chavePrivada);
        const assinaturaAlterada = assinatura.slice(0, -5) + 'XXXXX';
        const valida = await verificarAssinaturaRsa(undefined, texto, assinaturaAlterada, chavePublica);
        expect(valida).toBe(false);
    });

    it('ciclo completo de assinatura/verificação', async () => {
        const documentos = ['Doc 1', 'Contrato importante', 'Dados críticos'];
        for (const doc of documentos) {
            const assinatura = await assinarRsa(undefined, doc, chavePrivada);
            const valida = await verificarAssinaturaRsa(undefined, doc, assinatura, chavePublica);
            expect(valida).toBe(true);
        }
    });
});

describe('Separação de chaves RSA-OAEP e RSA-PSS', () => {
    it('chaves RSA-OAEP não devem funcionar para assinatura em navegadores', async () => {
        const parCripto = await gerarParChavesRsa(undefined, 2048);
        
        if (typeof parCripto.chavePublica === 'string') {
            expect(true).toBe(true);
            return;
        }
        
        const texto = 'Teste';
        await expect(async () => {
            await assinarRsa(undefined, texto, parCripto.chavePrivada);
        }).rejects.toThrow();
    });

    it('chaves RSA-PSS não devem funcionar para criptografia em navegadores', async () => {
        const parAssinatura = await gerarParChavesRsaAssinatura(undefined, 2048);
        
        if (typeof parAssinatura.chavePublica === 'string') {
            expect(true).toBe(true);
            return;
        }
        
        const texto = 'Teste';
        await expect(async () => {
            await criptografarRsa(undefined, texto, parAssinatura.chavePublica);
        }).rejects.toThrow();
    });
});

describe('Derivação de Chaves PBKDF2', () => {
    it('derivarChavePbkdf2 deve gerar chave', async () => {
        const senha = 'minha_senha';
        const sal = gerarSalt();
        const chave = await derivarChavePbkdf2(undefined, senha, sal);
        expect(chave).toBeTruthy();
        expect(chave).toHaveLength(64); // 32 bytes = 64 caracteres hex
        expect(chave).toMatch(/^[a-f0-9]+$/);
    });

    it('derivarChavePbkdf2 deve ser consistente com mesmos parâmetros', async () => {
        const senha = 'minha_senha';
        const sal = 'sal_fixo';
        const chave1 = await derivarChavePbkdf2(undefined, senha, sal, 1000, 32);
        const chave2 = await derivarChavePbkdf2(undefined, senha, sal, 1000, 32);
        expect(chave1).toBe(chave2);
    });

    it('derivarChavePbkdf2 deve gerar chaves diferentes com sais diferentes', async () => {
        const senha = 'minha_senha';
        const sal1 = gerarSalt();
        const sal2 = gerarSalt();
        const chave1 = await derivarChavePbkdf2(undefined, senha, sal1);
        const chave2 = await derivarChavePbkdf2(undefined, senha, sal2);
        expect(chave1).not.toBe(chave2);
    });

    it('derivarChavePbkdf2 deve gerar chaves diferentes com senhas diferentes', async () => {
        const sal = gerarSalt();
        const chave1 = await derivarChavePbkdf2(undefined, 'senha1', sal);
        const chave2 = await derivarChavePbkdf2(undefined, 'senha2', sal);
        expect(chave1).not.toBe(chave2);
    });

    it('derivarChavePbkdf2 deve respeitar tamanho de chave customizado', async () => {
        const senha = 'minha_senha';
        const sal = gerarSalt();
        const chave = await derivarChavePbkdf2(undefined, senha, sal, 1000, 16);
        expect(chave).toHaveLength(32); // 16 bytes = 32 caracteres hex
    });
});

describe('Cifra XOR', () => {
    it('cifrarXor deve cifrar texto', () => {
        const texto = 'Olá Mundo';
        const chave = 'chave123';
        const cifrado = cifrarXor(undefined, texto, chave);
        
        expect(cifrado).toBeTruthy();
        expect(typeof cifrado).toBe('string');
        expect(cifrado).toMatch(/^[a-f0-9]+$/);
        expect(cifrado).not.toBe(texto);
    });

    it('decifrarXor deve recuperar texto original', () => {
        const texto = 'Mensagem secreta';
        const chave = 'minhaChave';
        
        const cifrado = cifrarXor(undefined, texto, chave);
        const decifrado = decifrarXor(undefined, cifrado, chave);
        
        expect(decifrado).toBe(texto);
    });

    it('XOR deve ser simétrico', () => {
        const texto = 'Teste de simetria';
        const chave = 'abc123';
        
        const cifrado1 = cifrarXor(undefined, texto, chave);
        const cifrado2 = cifrarXor(undefined, texto, chave);
        
        expect(cifrado1).toBe(cifrado2);
    });

    it('cifrarXor deve funcionar com caracteres especiais', () => {
        const texto = 'Olá! 123 @#$%';
        const chave = 'key';
        
        const cifrado = cifrarXor(undefined, texto, chave);
        const decifrado = decifrarXor(undefined, cifrado, chave);
        
        expect(decifrado).toBe(texto);
    });

    it('cifrarXor deve lançar erro com chave vazia', () => {
        expect(() => {
            cifrarXor(undefined, 'texto', '');
        }).toThrow('A chave não pode estar vazia');
    });

    it('chaves diferentes devem produzir resultados diferentes', () => {
        const texto = 'Mesmo texto';
        const cifrado1 = cifrarXor(undefined, texto, 'chave1');
        const cifrado2 = cifrarXor(undefined, texto, 'chave2');
        
        expect(cifrado1).not.toBe(cifrado2);
    });
});

describe('ROT13', () => {
    it('rot13 deve cifrar letras', () => {
        const texto = 'Hello World';
        const cifrado = rot13(undefined, texto);
        
        expect(cifrado).toBe('Uryyb Jbeyq');
    });

    it('rot13 aplicado duas vezes deve retornar o original', () => {
        const texto = 'The quick brown fox';
        const cifrado = rot13(undefined, texto);
        const original = rot13(undefined, cifrado);
        
        expect(original).toBe(texto);
    });

    it('rot13 deve preservar maiúsculas e minúsculas', () => {
        expect(rot13(undefined, 'ABC')).toBe('NOP');
        expect(rot13(undefined, 'abc')).toBe('nop');
        expect(rot13(undefined, 'XyZ')).toBe('KlM');
    });

    it('rot13 não deve alterar números e símbolos', () => {
        const texto = 'Test 123 !@# 456';
        const cifrado = rot13(undefined, texto);
        
        expect(cifrado).toContain('123');
        expect(cifrado).toContain('!@#');
        expect(cifrado).toContain('456');
    });

    it('rot13 deve funcionar com alfabeto completo', () => {
        const alfabeto = 'abcdefghijklmnopqrstuvwxyz';
        const esperado = 'nopqrstuvwxyzabcdefghijklm';
        
        expect(rot13(undefined, alfabeto)).toBe(esperado);
    });
});

describe('ROT-N (Cifra de César)', () => {
    it('rotN com deslocamento 1 deve cifrar corretamente', () => {
        expect(rotN(undefined, 'abc', 1)).toBe('bcd');
        expect(rotN(undefined, 'xyz', 1)).toBe('yza');
    });

    it('rotN com deslocamento 13 deve ser igual a rot13', () => {
        const texto = 'Hello World';
        expect(rotN(undefined, texto, 13)).toBe(rot13(undefined, texto));
    });

    it('rotN deve aceitar deslocamento padrão de 13', () => {
        const texto = 'Test';
        expect(rotN(undefined, texto)).toBe(rotN(undefined, texto, 13));
    });

    it('decifrarRotN deve recuperar texto original', () => {
        const texto = 'Mensagem secreta';
        const deslocamento = 7;
        
        const cifrado = rotN(undefined, texto, deslocamento);
        const decifrado = decifrarRotN(undefined, cifrado, deslocamento);
        
        expect(decifrado).toBe(texto);
    });

    it('rotN deve normalizar deslocamentos grandes', () => {
        const texto = 'abc';
        // 27 = 1 (mod 26)
        expect(rotN(undefined, texto, 27)).toBe(rotN(undefined, texto, 1));
        // 52 = 0 (mod 26)
        expect(rotN(undefined, texto, 52)).toBe(texto);
    });

    it('rotN deve funcionar com deslocamento negativo', () => {
        const texto = 'abc';
        expect(rotN(undefined, texto, -1)).toBe('zab');
    });

    it('rotN deve preservar maiúsculas e minúsculas', () => {
        expect(rotN(undefined, 'ABC', 1)).toBe('BCD');
        expect(rotN(undefined, 'xyz', 1)).toBe('yza');
    });

    it('rotN não deve alterar caracteres não-alfabéticos', () => {
        const texto = 'Test 123 !@#';
        const cifrado = rotN(undefined, texto, 5);
        
        expect(cifrado).toContain('123');
        expect(cifrado).toContain('!@#');
        expect(cifrado).toContain(' ');
    });

    it('ciclo completo com vários deslocamentos', () => {
        const texto = 'Criptografia é divertida!';
        
        for (let d = 1; d < 26; d++) {
            const cifrado = rotN(undefined, texto, d);
            const decifrado = decifrarRotN(undefined, cifrado, d);
            expect(decifrado).toBe(texto);
        }
    });
});
