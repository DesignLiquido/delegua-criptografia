import { gerarTextoAleatorio } from "./aleatorios";

/**
 * Gera um salt aleatório para uso em derivação de chaves.
 * @param tamanho Tamanho do salt em bytes (padrão: 16)
 * @returns Salt em formato hexadecimal
 */
export function gerarSalt(interpretador?: any, tamanho: number = 16): string {
    if (!tamanho) {
        tamanho = 16;
    }

    return gerarTextoAleatorio(interpretador, tamanho);
}