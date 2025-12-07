import {
  criptografarEmMeninoDoAcre,
  descriptografarDeMeninoDoAcre,
} from "../fontes/menino-do-acre";

describe("Criptografia Menino do Acre", () => {
  test("criptografar e descriptografar com tema rúnico", () => {
    const original = "delegua";
    const criptografado = criptografarEmMeninoDoAcre({}, original, { tema: "runico" });
    const descriptografado = descriptografarDeMeninoDoAcre({}, criptografado, { tema: "runico" });
    expect(descriptografado).toBe(original);
  });

  test("criptografar e descriptografar com tema alquímico", () => {
    const original = "delegua";
    const criptografado = criptografarEmMeninoDoAcre({}, original, { tema: "alquimico" });
    const descriptografado = descriptografarDeMeninoDoAcre({}, criptografado, { tema: "alquimico" });
    expect(descriptografado).toBe(original);
  });

  test("criptografar e descriptografar com tema híbrido", () => {
    const original = "delegua";
    const criptografado = criptografarEmMeninoDoAcre({}, original, { tema: "hibrido" });
    const descriptografado = descriptografarDeMeninoDoAcre({}, criptografado, { tema: "hibrido" });
    expect(descriptografado).toBe(original);
  });

  test("preserva caracteres não mapeados", () => {
    const original = "123 !?";
    const criptografado = criptografarEmMeninoDoAcre({}, original, { tema: "hibrido" });
    expect(criptografado).toBe(original);
  });
});