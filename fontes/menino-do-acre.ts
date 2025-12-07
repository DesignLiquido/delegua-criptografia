/*
  delegua-criptografia: tema híbrido inspirado no "Menino do Acre"
  Vogais → Runic (U+16A0–U+16FF)
  Consoantes → Alchemical Symbols (U+1F700–U+1F77F)
*/

export type TemaCriptografiaMeninoDoAcre = 'runico' | 'alquimico' | 'hibrido';

export interface OpcoesCriptografiaMeninoDoAcre {
  tema?: TemaCriptografiaMeninoDoAcre;
  preservarMaiusculas?: boolean;
  normalizar?: boolean;
}

// --- Mapas ---
const vogais = ['a', 'e', 'i', 'o', 'u'];

// --- Mapeamento Rúnico ---
const mapaRunico: Record<string, string> = {
  a: "ᚠ", b: "ᚢ", c: "ᚦ", d: "ᚨ", e: "ᚱ", f: "ᚲ", g: "ᚷ",
  h: "ᚹ", i: "ᚺ", j: "ᚾ", k: "ᛁ", l: "ᛃ", m: "ᛇ", n: "ᛈ",
  o: "ᛉ", p: "ᛋ", q: "ᛏ", r: "ᛒ", s: "ᛖ", t: "ᛗ", u: "ᛚ",
  v: "ᛜ", w: "ᛞ", x: "ᛟ", y: "ᚤ", z: "ᚣ",
};

// --- Mapeamento Alquímico ---
const mapaAlquimico: Record<string, string> = {
  a: "🜁", b: "🜂", c: "🜃", d: "🜄", e: "🜅", f: "🜆", g: "🜇",
  h: "🜈", i: "🜉", j: "🜊", k: "🜋", l: "🜌", m: "🜍", n: "🜎",
  o: "🜏", p: "🜐", q: "🜑", r: "🜒", s: "🜓", t: "🜔", u: "🜕",
  v: "🜖", w: "🜗", x: "🜘", y: "🜙", z: "🜚",
};

// --- Reversos ---
const mapaRunicoReverso = Object.fromEntries(Object.entries(mapaRunico).map(([lat, rune]) => [rune, lat]));
const mapaAlquimicoReverso = Object.fromEntries(Object.entries(mapaAlquimico).map(([lat, simb]) => [simb, lat]));

/**
 * Criptografa texto latino (a–z, A–Z) em símbolos do tema escolhido.
 */
export function criptografarEmMeninoDoAcre(
  interpretador: any,
  texto: string,
  opcoes: OpcoesCriptografiaMeninoDoAcre = {
    tema: 'runico', 
    preservarMaiusculas: false, 
    normalizar: false
  }
): string {
  const { tema, preservarMaiusculas, normalizar } = opcoes ?? {
    tema: 'runico', 
    preservarMaiusculas: false, 
    normalizar: false
  };
  const origem = normalizar ? texto.normalize("NFKC") : texto;

  return [...origem]
    .map((caracter) => {
      const minusculo = caracter.toLowerCase();
      let simboloResolvido: string | undefined;

      if (tema === 'runico') simboloResolvido = mapaRunico[minusculo];
      else if (tema === 'alquimico') simboloResolvido = mapaAlquimico[minusculo];
      else if (tema === 'hibrido') {
        simboloResolvido = vogais.includes(minusculo) ? mapaRunico[minusculo] : mapaAlquimico[minusculo];
      }

      if (simboloResolvido) return simboloResolvido;
      return preservarMaiusculas ? caracter : caracter;
    })
    .join("");
}

/**
 * Descriptografa símbolos de volta para letras minúsculas latinas.
 */
export function descriptografarDeMeninoDoAcre(
  interpretador: any,
  textoCriptografado: string,
  opcoes: OpcoesCriptografiaMeninoDoAcre = {
    tema: 'runico',
    normalizar: false
  }
): string {
  const { tema, normalizar } = opcoes ?? {
    tema: 'runico', normalizar: false
  };
  const src = normalizar ? textoCriptografado.normalize("NFKC") : textoCriptografado;

  return [...src]
    .map((ch) => {
      let lat: string | undefined;
      if (tema === 'runico') lat = mapaRunicoReverso[ch];
      else if (tema === 'alquimico') lat = mapaAlquimicoReverso[ch];
      else if (tema === 'hibrido') {
        lat = mapaRunicoReverso[ch] ?? mapaAlquimicoReverso[ch];
      }
      return lat ?? ch;
    })
    .join("");
}