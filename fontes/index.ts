/**
 * Biblioteca de criptografia para Delégua.
 * Compatível com Node.js e navegadores.
*/

import {
    criptografarAes256,
    descriptografarAes256
} from './aes';
import {
    gerarBytesAleatorios,
    gerarTextoAleatorio,
    gerarUuid
} from './aleatorios';
import {
    codificarBase64,
    decodificarBase64
} from './base64';
import {
    cifrarXor,
    decifrarXor,
    rot13,
    rotN,
    decifrarRotN
} from './educacionais';
import {
    md5,
    sha1,
    sha256,
    sha512,
    hmacSha256,
    hmacSha512
} from './hashes';
import { criptografarEmMeninoDoAcre, descriptografarDeMeninoDoAcre } from './menino-do-acre';
import {
    derivarChavePbkdf2
} from './pbkdf2';
import {
    gerarParChavesRsa,
    gerarParChavesRsaAssinatura,
    criptografarRsa,
    descriptografarRsa,
    assinarRsa,
    verificarAssinaturaRsa
} from './rsa';
import { gerarSalt } from './salt';

// Exportação padrão com todas as funções
export default {
    md5,
    sha1,
    sha256,
    sha512,
    hmacSha256,
    hmacSha512,
    gerarBytesAleatorios,
    gerarTextoAleatorio,
    gerarUuid,
    codificarBase64,
    decodificarBase64,
    criptografarAes256,
    descriptografarAes256,
    gerarParChavesRsa,
    gerarParChavesRsaAssinatura,
    criptografarRsa,
    descriptografarRsa,
    assinarRsa,
    verificarAssinaturaRsa,
    derivarChavePbkdf2,
    gerarSalt,
    cifrarXor,
    decifrarXor,
    rot13,
    rotN,
    decifrarRotN,
    criptografarEmMeninoDoAcre,
    descriptografarDeMeninoDoAcre
};