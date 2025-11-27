import { assinarRsa, codificarBase64, criptografarAes256, criptografarRsa, decodificarBase64, derivarChavePbkdf2, descriptografarAes256, gerarBytesAleatorios, gerarParChavesRsa, gerarSalt, gerarUuid, hmacSha256, hmacSha512, md5, sha1, sha256, sha512, verificarAssinaturaRsa } from "./index";

export const DeleguaModuloCriptografia = {
    md5: {
        tipoRetorno: 'texto',
        funcao: md5,
        argumentos: [{ nome: 'texto', tipo: 'texto' }]
    },
    sha1: {
        tipoRetorno: 'texto',
        funcao: sha1,
        argumentos: [{ nome: 'texto', tipo: 'texto' }]
    },
    sha256: {
        tipoRetorno: 'texto',
        funcao: sha256,
        argumentos: [{ nome: 'texto', tipo: 'texto' }]
    },
    sha512: {
        tipoRetorno: 'texto',
        funcao: sha512,
        argumentos: [{ nome: 'texto', tipo: 'texto' }]
    },
    hmacSha256: {
        tipoRetorno: 'texto',
        funcao: hmacSha256,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ]
    },
    hmacSha512: {
        tipoRetorno: 'texto',
        funcao: hmacSha512,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ]
    },
    gerarBytesAleatorios: {
        tipoRetorno: 'bytes',
        funcao: gerarBytesAleatorios,
        argumentos: [{ nome: 'tamanho', tipo: 'numero' }]
    },
    gerarUuid: {
        tipoRetorno: 'texto',
        funcao: gerarUuid,
        argumentos: []
    },
    codificarBase64: {
        tipoRetorno: 'texto',
        funcao: codificarBase64,
        argumentos: [{ nome: 'texto', tipo: 'texto' }]
    },
    decodificarBase64: {
        tipoRetorno: 'texto',
        funcao: decodificarBase64,
        argumentos: [{ nome: 'textoBase64', tipo: 'texto' }]
    },
    criptografarAes256: {
        tipoRetorno: 'texto',
        funcao: criptografarAes256,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ]
    },
    descriptografarAes256: {
        tipoRetorno: 'texto',
        funcao: descriptografarAes256,
        argumentos: [
            { nome: 'textoCriptografado', tipo: 'texto' },
            { nome: 'chave', tipo: 'texto' }
        ]
    },
    gerarParChavesRsa: {
        tipoRetorno: 'objeto',
        funcao: gerarParChavesRsa,
        argumentos: [{ nome: 'tamanhoChave', tipo: 'numero' }]
    },
    criptografarRsa: {
        tipoRetorno: 'texto',
        funcao: criptografarRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chavePublica', tipo: 'texto' }
        ]
    },
    assinarRsa: {
        tipoRetorno: 'texto',
        funcao: assinarRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'chavePrivada', tipo: 'texto' }
        ]
    },
    verificarAssinaturaRsa: {
        tipoRetorno: 'lógico',
        funcao: verificarAssinaturaRsa,
        argumentos: [
            { nome: 'texto', tipo: 'texto' },
            { nome: 'assinatura', tipo: 'texto' },
            { nome: 'chavePublica', tipo: 'texto' }
        ]
    },
    derivarChavePbkdf2: {
        tipoRetorno: 'texto',
        funcao: derivarChavePbkdf2,
        argumentos: [
            { nome: 'senha', tipo: 'texto' },
            { nome: 'sal', tipo: 'texto' },
            { nome: 'iteracoes', tipo: 'numero', opcional: true },
            { nome: 'tamanhoChave', tipo: 'numero', opcional: true }
        ]
    },
    gerarSalt: {
        tipoRetorno: 'texto',
        funcao: gerarSalt,
        argumentos: [
            { nome: 'tamanho', tipo: 'numero', opcional: true }
        ]
    }
}
