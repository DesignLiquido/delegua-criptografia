import { assinarRsa, codificarBase64, criptografarAes256, criptografarRsa, decodificarBase64, derivarChavePbkdf2, descriptografarAes256, gerarBytesAleatorios, gerarParChavesRsa, gerarParChavesRsaAssinatura, gerarSalt, gerarUuid, hmacSha256, hmacSha512, md5, sha1, sha256, sha512, verificarAssinaturaRsa } from "./index";

export const DeleguaModuloCriptografia = {
    md5: {
        tipoRetorno: 'texto',
        funcao: md5,
        argumentos: [{ nome: 'texto', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.md5(texto)\`\n\n` +
            'Gera uma dispersão (_hash_) MD5 de um texto.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var meuTexto = "Olá Mundo"\n' +
            `escreva(criptografia.md5(meuTexto)) // "7141e6862d77e5c2a8e2f60a77a153cd"\n`,
        exemploCodigo: 'criptografia.md5("Meu texto")',
    },
    sha1: {
        tipoRetorno: 'texto',
        funcao: sha1,
        argumentos: [{ nome: 'texto', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.sha1(texto)\`\n\n` +
            'Gera uma dispersão (_hash_) SHA-1 de um texto.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var meuTexto = "Olá Mundo"\n' +
            `escreva(criptografia.sha1(meuTexto)) // Gera um hash SHA-1\n` +
            '```\n',
        exemploCodigo: 'criptografia.sha1("Meu texto")'
    },
    sha256: {
        tipoRetorno: 'texto',
        funcao: sha256,
        argumentos: [{ nome: 'texto', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.sha256(texto)\`\n\n` +
            'Gera uma dispersão (_hash_) SHA-256 de um texto.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var meuTexto = "Olá Mundo"\n' +
            `escreva(criptografia.sha256(meuTexto)) // Gera um hash SHA-256\n` +
            '```\n',
        exemploCodigo: 'criptografia.sha256("Meu texto")'
    },
    sha512: {
        tipoRetorno: 'texto',
        funcao: sha512,
        argumentos: [{ nome: 'texto', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.sha512(texto)\`\n\n` +
            'Gera uma dispersão (_hash_) SHA-512 de um texto.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var meuTexto = "Olá Mundo"\n' +
            `escreva(criptografia.sha512(meuTexto)) // Gera um hash SHA-512\n` +
            '```\n',
        exemploCodigo: 'criptografia.sha512("Meu texto")'
    },
    hmacSha256: {
        tipoRetorno: 'texto',
        funcao: hmacSha256,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.hmacSha256(texto, chave)\`\n\n` +
            'Gera um código de autenticação de mensagem (HMAC) usando SHA-256.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var mensagem = "mensagem"\n' +
            'var chave = "chave-secreta"\n' +
            `escreva(criptografia.hmacSha256(mensagem, chave)) // Gera um HMAC SHA-256\n` +
            '```\n',
        exemploCodigo: 'criptografia.hmacSha256("mensagem", "chave-secreta")'
    },
    hmacSha512: {
        tipoRetorno: 'texto',
        funcao: hmacSha512,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.hmacSha512(texto, chave)\`\n\n` +
            'Gera um código de autenticação de mensagem (HMAC) usando SHA-512.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var mensagem = "mensagem"\n' +
            'var chave = "chave-secreta"\n' +
            `escreva(criptografia.hmacSha512(mensagem, chave)) // Gera um HMAC SHA-512\n` +
            '```\n',
        exemploCodigo: 'criptografia.hmacSha512("mensagem", "chave-secreta")'
    },
    gerarBytesAleatorios: {
        tipoRetorno: 'bytes',
        funcao: gerarBytesAleatorios,
        argumentos: [{ nome: 'tamanho', tipo: 'numero' }],
        documentacao:
            `# \`criptografia.gerarBytesAleatorios(tamanho)\`\n\n` +
            'Gera bytes aleatórios criptograficamente seguros.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var bytes = criptografia.gerarBytesAleatorios(16)\n' +
            `escreva(bytes) // Gera 16 bytes aleatórios\n` +
            '```\n',
        exemploCodigo: 'criptografia.gerarBytesAleatorios(16)'
    },
    gerarUuid: {
        tipoRetorno: 'texto',
        funcao: gerarUuid,
        argumentos: [],
        documentacao:
            `# \`criptografia.gerarUuid()\`\n\n` +
            'Gera um identificador único universal (UUID) versão 4.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var uuid = criptografia.gerarUuid()\n' +
            `escreva(uuid) // Ex: "f47ac10b-58cc-4372-a567-0e02b2c3d479"\n` +
            '```\n',
        exemploCodigo: 'criptografia.gerarUuid()'
    },
    codificarBase64: {
        tipoRetorno: 'texto',
        funcao: codificarBase64,
        argumentos: [{ nome: 'texto', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.codificarBase64(texto)\`\n\n` +
            'Codifica um texto em formato Base64.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var texto = "Texto para codificar"\n' +
            `escreva(criptografia.codificarBase64(texto)) // Retorna texto em Base64\n` +
            '```\n',
        exemploCodigo: 'criptografia.codificarBase64("Texto para codificar")'
    },
    decodificarBase64: {
        tipoRetorno: 'texto',
        funcao: decodificarBase64,
        argumentos: [{ nome: 'textoBase64', tipo: 'texto' }],
        documentacao:
            `# \`criptografia.decodificarBase64(textoBase64)\`\n\n` +
            'Decodifica um texto em formato Base64.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var codificado = criptografia.codificarBase64("Olá")\n' +
            `var decodificado = criptografia.decodificarBase64(codificado)\n` +
            `escreva(decodificado) // "Olá"\n` +
            '```\n',
        exemploCodigo: 'criptografia.decodificarBase64("VGV4dG8gY29kaWZpY2Fkbw==")'
    },
    criptografarAes256: {
        tipoRetorno: 'dicionário',
        funcao: criptografarAes256,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.criptografarAes256(texto, chave)\`\n\n` +
            'Criptografa um texto usando AES-256-CBC.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var texto = "Mensagem secreta"\n' +
            'var chave = "minha-chave-super-secreta-aqui!"\n' +
            `var resultado = criptografia.criptografarAes256(texto, chave)\n` +
            `escreva(resultado.textoCriptografado) // Texto criptografado\n` +
            `escreva(resultado.iv) // Vetor de inicialização\n` +
            '```\n',
        exemploCodigo: 'criptografia.criptografarAes256("Mensagem secreta", "chave-de-32-caracteres-exatos!")'
    },
    descriptografarAes256: {
        tipoRetorno: 'texto',
        funcao: descriptografarAes256,
        argumentos: [
            { nome: 'textoCriptografado', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' },
            { nome: 'iv', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.descriptografarAes256(textoCriptografado, chave, iv)\`\n\n` +
            'Descriptografa um texto criptografado com AES-256-CBC.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var chave = "minha-chave-super-secreta-aqui!"\n' +
            'var resultado = criptografia.criptografarAes256("Mensagem secreta", chave)\n' +
            `var descriptografado = criptografia.descriptografarAes256(resultado.textoCriptografado, chave, resultado.iv)\n` +
            `escreva(descriptografado) // "Mensagem secreta"\n` +
            '```\n',
        exemploCodigo: 'criptografia.descriptografarAes256(textoCriptografado, chave, iv)'
    },
    gerarParChavesRsa: {
        tipoRetorno: 'dicionário',
        funcao: gerarParChavesRsa,
        argumentos: [{ nome: 'tamanhoChave', tipo: 'numero' }],
        documentacao:
            `# \`criptografia.gerarParChavesRsa(tamanhoChave)\`\n\n` +
            'Gera um par de chaves RSA (pública e privada).\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var par = criptografia.gerarParChavesRsa(2048)\n' +
            `escreva(par.chavePublica) // Chave pública em formato PEM\n` +
            `escreva(par.chavePrivada) // Chave privada em formato PEM\n` +
            '```\n',
        exemploCodigo: 'criptografia.gerarParChavesRsa(2048)'
    },
    gerarParChavesRsaAssinatura: {
        tipoRetorno: 'dicionário',
        funcao: gerarParChavesRsaAssinatura,
        argumentos: [{ nome: 'tamanhoModulo', tipo: 'numero' }],
        documentacao:
            `# \`criptografia.gerarParChavesRsaAssinatura(tamanhoModulo)\`\n\n` +
            'Gera um par de chaves RSA (pública e privada) para assinatura digital.\n' +
            '\n\n ## Exemplo de Código\n' +
            'var criptografia = importar("criptografia")\n' +
            'var par = criptografia.gerarParChavesRsaAssinatura(2048)\n' +
            'var documento = "Texto importante"\n' +
            'var assinatura = criptografia.assinarRsa(documento, par.chavePrivada)\n' +
            'var valida = criptografia.verificarAssinaturaRsa(documento, assinatura, par.chavePublica)\n' +
            `escreva(valida) // verdadeiro\n` +
            '```\n',
        exemploCodigo: 'criptografia.gerarParChavesRsa(2048)'
    },
    criptografarRsa: {
        tipoRetorno: 'texto',
        funcao: criptografarRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chavePublica', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.criptografarRsa(texto, chavePublica)\`\n\n` +
            'Criptografa um texto usando uma chave pública RSA.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var par = criptografia.gerarParChavesRsa(2048)\n' +
            'var texto = "Mensagem confidencial"\n' +
            `var criptografado = criptografia.criptografarRsa(texto, par.chavePublica)\n` +
            `escreva(criptografado) // Texto criptografado em Base64\n` +
            '```\n',
        exemploCodigo: 'criptografia.criptografarRsa("Mensagem confidencial", chavePublica)'
    },
    assinarRsa: {
        tipoRetorno: 'texto',
        funcao: assinarRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chavePrivada', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.assinarRsa(texto, chavePrivada)\`\n\n` +
            'Assina digitalmente um texto usando uma chave privada RSA.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var par = criptografia.gerarParChavesRsa(2048)\n' +
            'var texto = "Documento importante"\n' +
            `var assinatura = criptografia.assinarRsa(texto, par.chavePrivada)\n` +
            `escreva(assinatura) // Assinatura em Base64\n` +
            '```\n',
        exemploCodigo: 'criptografia.assinarRsa("Documento importante", chavePrivada)'
    },
    verificarAssinaturaRsa: {
        tipoRetorno: 'lógico',
        funcao: verificarAssinaturaRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'assinatura', tipo: 'texto' },
            { nome: 'chavePublica', tipo: 'texto' }
        ],
        documentacao:
            `# \`criptografia.verificarAssinaturaRsa(texto, assinatura, chavePublica)\`\n\n` +
            'Verifica uma assinatura digital usando uma chave pública RSA.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var par = criptografia.gerarParChavesRsa(2048)\n' +
            'var texto = "Documento importante"\n' +
            'var assinatura = criptografia.assinarRsa(texto, par.chavePrivada)\n' +
            `var valida = criptografia.verificarAssinaturaRsa(texto, assinatura, par.chavePublica)\n` +
            `escreva(valida) // verdadeiro\n` +
            '```\n',
        exemploCodigo: 'criptografia.verificarAssinaturaRsa(texto, assinatura, chavePublica)'
    },
    derivarChavePbkdf2: {
        tipoRetorno: 'texto',
        funcao: derivarChavePbkdf2,
        argumentos: [
            { nome: 'senha', tipo: 'texto' },
            { nome: 'sal', tipo: 'texto' },
            { nome: 'iteracoes', tipo: 'número', opcional: true, valorPadrao: 100000 },
            { nome: 'tamanhoChave', tipo: 'número', opcional: true, valorPadrao: 32 }
        ],
        documentacao:
            `# \`criptografia.derivarChavePbkdf2(senha, sal, iteracoes?, tamanhoChave?)\`\n\n` +
            'Deriva uma chave a partir de uma senha usando PBKDF2 (Password-Based Key Derivation Function 2, ou Função de Derivação de Chave Baseada em Senha versão 2).\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var senha = "minha_senha"\n' +
            'var sal = criptografia.gerarSalt()\n' +
            `var chave = criptografia.derivarChavePbkdf2(senha, sal)\n` +
            `escreva(chave) // Chave derivada em hexadecimal\n` +
            '```\n',
        exemploCodigo: 'criptografia.derivarChavePbkdf2("minha_senha", sal)'
    },
    gerarSalt: {
        tipoRetorno: 'texto',
        funcao: gerarSalt,
        argumentos: [
            { nome: 'tamanho', tipo: 'numero', opcional: true, valorPadrao: 16 }
        ],
        documentacao:
            `# \`criptografia.gerarSalt(tamanho?)\`\n\n` +
            'Gera um salt (valor aleatório) para uso em derivação de chaves.\n' +
            '\n\n ## Exemplo de Código\n' +
            '\n\n```delegua\n' +
            'var criptografia = importar("criptografia")\n' +
            'var salt = criptografia.gerarSalt()\n' +
            `escreva(salt) // Salt aleatório em hexadecimal\n` +
            'var saltCustomizado = criptografia.gerarSalt(32)\n' +
            `escreva(saltCustomizado) // Salt de 32 bytes em hexadecimal\n` +
            '```\n',
        exemploCodigo: 'criptografia.gerarSalt()'
    }
}
