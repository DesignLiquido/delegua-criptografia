import {
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
} from '../fontes';

describe('Funções de Hash', () => {
    const texto = 'Olá Mundo';

    it('md5 deve gerar hash correto', () => {
        const hash = md5(undefined, texto);
        expect(hash).toHaveLength(32);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha1 deve gerar hash correto', () => {
        const hash = sha1(undefined, texto);
        expect(hash).toHaveLength(40);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha256 deve gerar hash correto', () => {
        const hash = sha256(undefined, texto);
        expect(hash).toHaveLength(64);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('sha512 deve gerar hash correto', () => {
        const hash = sha512(undefined, texto);
        expect(hash).toHaveLength(128);
        expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it('hashes devem ser consistentes', () => {
        const hash1 = sha256(undefined, texto);
        const hash2 = sha256(undefined, texto);
        expect(hash1).toBe(hash2);
    });
});

describe('Funções HMAC', () => {
    const texto = 'mensagem';
    const chave = 'chave-secreta';

    it('hmacSha256 deve gerar HMAC correto', () => {
        const hmac = hmacSha256(undefined, texto, chave);
        expect(hmac).toHaveLength(64);
        expect(hmac).toMatch(/^[a-f0-9]+$/);
    });

    it('hmacSha512 deve gerar HMAC correto', () => {
        const hmac = hmacSha512(undefined, texto, chave);
        expect(hmac).toHaveLength(128);
        expect(hmac).toMatch(/^[a-f0-9]+$/);
    });

    it('HMACs devem ser consistentes com mesma chave', () => {
        const hmac1 = hmacSha256(undefined, texto, chave);
        const hmac2 = hmacSha256(undefined, texto, chave);
        expect(hmac1).toBe(hmac2);
    });

    it('HMACs devem ser diferentes com chaves diferentes', () => {
        const hmac1 = hmacSha256(undefined, texto, chave);
        const hmac2 = hmacSha256(undefined, texto, 'outra-chave');
        expect(hmac1).not.toBe(hmac2);
    });
});

describe('Geração de Dados Aleatórios', () => {
    it('gerarBytesAleatorios deve gerar buffer do tamanho correto', () => {
        const bytes = gerarBytesAleatorios(undefined, 16);
        expect(bytes).toBeInstanceOf(Buffer);
        expect(bytes.length).toBe(16);
    });

    it('gerarStringAleatoria deve gerar string do tamanho correto', () => {
        const str = gerarStringAleatoria(undefined, 16);
        expect(str).toHaveLength(32); // 16 bytes = 32 caracteres hex
        expect(str).toMatch(/^[a-f0-9]+$/);
    });

    it('gerarStringAleatoria deve gerar valores diferentes', () => {
        const str1 = gerarStringAleatoria(undefined, 16);
        const str2 = gerarStringAleatoria(undefined, 16);
        expect(str1).not.toBe(str2);
    });

    it('gerarUuid deve gerar UUID válido', () => {
        const uuid = gerarUuid();
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        expect(uuid).toMatch(uuidRegex);
    });

    it('gerarSal deve gerar salt do tamanho correto', () => {
        const sal = gerarSalt(16);
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

    it('criptografarAes256 deve retornar objeto com campos corretos', () => {
        const resultado = criptografarAes256(undefined, texto, chave);
        expect(resultado).toHaveProperty('textoCriptografado');
        expect(resultado).toHaveProperty('iv');
        expect(typeof resultado.textoCriptografado).toBe('string');
        expect(typeof resultado.iv).toBe('string');
    });

    it('descriptografarAes256 deve recuperar texto original', () => {
        const resultado = criptografarAes256(undefined, texto, chave);
        const descriptografado = descriptografarAes256(
            undefined, 
            resultado.textoCriptografado,
            chave,
            resultado.iv
        );
        expect(descriptografado).toBe(texto);
    });

    it('textos diferentes devem gerar criptografias diferentes', () => {
        const resultado1 = criptografarAes256(undefined, 'texto1', chave);
        const resultado2 = criptografarAes256(undefined, 'texto2', chave);
        expect(resultado1.textoCriptografado).not.toBe(resultado2.textoCriptografado);
    });

    it('mesmo texto deve gerar IVs diferentes em criptografias diferentes', () => {
        const resultado1 = criptografarAes256(undefined, texto, chave);
        const resultado2 = criptografarAes256(undefined, texto, chave);
        expect(resultado1.iv).not.toBe(resultado2.iv);
        expect(resultado1.textoCriptografado).not.toBe(resultado2.textoCriptografado);
    });
});

describe('Criptografia RSA', () => {
    let chavePublica: string;
    let chavePrivada: string;

    beforeAll(() => {
        const par = gerarParChavesRsa(2048);
        chavePublica = par.chavePublica;
        chavePrivada = par.chavePrivada;
    });

    it('gerarParChavesRsa deve gerar par de chaves válido', () => {
        const par = gerarParChavesRsa(2048);
        expect(par.chavePublica).toContain('BEGIN PUBLIC KEY');
        expect(par.chavePublica).toContain('END PUBLIC KEY');
        expect(par.chavePrivada).toContain('BEGIN PRIVATE KEY');
        expect(par.chavePrivada).toContain('END PRIVATE KEY');
    });

    it('criptografarRsa deve criptografar texto', () => {
        const texto = 'Mensagem confidencial';
        const criptografado = criptografarRsa(undefined, texto, chavePublica);
        expect(criptografado).toBeTruthy();
        expect(typeof criptografado).toBe('string');
        expect(criptografado).not.toBe(texto);
    });

    it('descriptografarRsa deve recuperar texto original', () => {
        const texto = 'Mensagem confidencial';
        const criptografado = criptografarRsa(undefined, texto, chavePublica);
        const descriptografado = descriptografarRsa(undefined, criptografado, chavePrivada);
        expect(descriptografado).toBe(texto);
    });

    it('ciclo completo de criptografia/descriptografia RSA', () => {
        const textos = ['Olá', 'Teste 123', 'Dados sensíveis'];
        textos.forEach(texto => {
            const criptografado = criptografarRsa(undefined, texto, chavePublica);
            const descriptografado = descriptografarRsa(undefined, criptografado, chavePrivada);
            expect(descriptografado).toBe(texto);
        });
    });
});

describe('Assinatura Digital RSA', () => {
    let chavePublica: string;
    let chavePrivada: string;

    beforeAll(() => {
        const par = gerarParChavesRsa(2048);
        chavePublica = par.chavePublica;
        chavePrivada = par.chavePrivada;
    });

    it('assinarRsa deve gerar assinatura', () => {
        const texto = 'Documento importante';
        const assinatura = assinarRsa(undefined, texto, chavePrivada);
        expect(assinatura).toBeTruthy();
        expect(typeof assinatura).toBe('string');
    });

    it('verificarAssinaturaRsa deve validar assinatura correta', () => {
        const texto = 'Documento importante';
        const assinatura = assinarRsa(undefined, texto, chavePrivada);
        const valida = verificarAssinaturaRsa(undefined, texto, assinatura, chavePublica);
        expect(valida).toBe(true);
    });

    it('verificarAssinaturaRsa deve rejeitar assinatura inválida', () => {
        const texto = 'Documento importante';
        const assinatura = assinarRsa(undefined, texto, chavePrivada);
        const textoAlterado = 'Documento importante modificado';
        const valida = verificarAssinaturaRsa(undefined, textoAlterado, assinatura, chavePublica);
        expect(valida).toBe(false);
    });

    it('verificarAssinaturaRsa deve rejeitar assinatura adulterada', () => {
        const texto = 'Documento importante';
        const assinatura = assinarRsa(undefined, texto, chavePrivada);
        const assinaturaAlterada = assinatura.slice(0, -5) + 'XXXXX';
        const valida = verificarAssinaturaRsa(undefined, texto, assinaturaAlterada, chavePublica);
        expect(valida).toBe(false);
    });
});

describe('Derivação de Chaves PBKDF2', () => {
    it('derivarChavePbkdf2 deve gerar chave', () => {
        const senha = 'minha_senha';
        const sal = gerarSalt();
        const chave = derivarChavePbkdf2(undefined, senha, sal);
        expect(chave).toBeTruthy();
        expect(chave).toHaveLength(64); // 32 bytes = 64 caracteres hex
        expect(chave).toMatch(/^[a-f0-9]+$/);
    });

    it('derivarChavePbkdf2 deve ser consistente com mesmos parâmetros', () => {
        const senha = 'minha_senha';
        const sal = 'sal_fixo';
        const chave1 = derivarChavePbkdf2(undefined, senha, sal, 1000, 32);
        const chave2 = derivarChavePbkdf2(undefined, senha, sal, 1000, 32);
        expect(chave1).toBe(chave2);
    });

    it('derivarChavePbkdf2 deve gerar chaves diferentes com sais diferentes', () => {
        const senha = 'minha_senha';
        const sal1 = gerarSalt();
        const sal2 = gerarSalt();
        const chave1 = derivarChavePbkdf2(undefined, senha, sal1);
        const chave2 = derivarChavePbkdf2(undefined, senha, sal2);
        expect(chave1).not.toBe(chave2);
    });

    it('derivarChavePbkdf2 deve gerar chaves diferentes com senhas diferentes', () => {
        const sal = gerarSalt();
        const chave1 = derivarChavePbkdf2(undefined, 'senha1', sal);
        const chave2 = derivarChavePbkdf2(undefined, 'senha2', sal);
        expect(chave1).not.toBe(chave2);
    });

    it('derivarChavePbkdf2 deve respeitar tamanho de chave customizado', () => {
        const senha = 'minha_senha';
        const sal = gerarSalt();
        const chave = derivarChavePbkdf2(undefined, senha, sal, 1000, 16);
        expect(chave).toHaveLength(32); // 16 bytes = 32 caracteres hex
    });
});
