import SignatureModule from "./SignatureModule";
import { PublicKey } from "./SignatureModule.types";

export async function generateEllipticCurveKeys(
  alias: string,
): Promise<PublicKey> {
  return await SignatureModule.generateEllipticCurveKeys(alias);
}
