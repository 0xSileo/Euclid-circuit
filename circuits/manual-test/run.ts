import { generateTestData, getCircuit } from "./utils";

async function main() {
  const payload = "Hello World";

  const testData = generateTestData(payload);
  const circuit = await getCircuit("rsa-verifier");

  const { inputs } = testData;
  const witness = await circuit.calculateWitness(inputs);
  await circuit.checkConstraints(witness);
}

main();
