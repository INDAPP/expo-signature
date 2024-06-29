import SignatureModule from "./SignatureModule";
import { PublicKey } from "./SignatureModule.types";

export async function generateEllipticCurveKeys(
  alias: string,
): Promise<PublicKey> {
  return await SignatureModule.generateEllipticCurveKeys(alias);
}

export async function getEllipticCurvePublicKey(
  alias: string,
): Promise<PublicKey | null> {
  return await SignatureModule.getEllipticCurvePublicKey(alias);
}

export async function isKeyPresentInKeychain(alias: string): Promise<boolean> {
  return await SignatureModule.isKeyPresentInKeychain(alias);
}

export async function deleteKey(alias: string): Promise<boolean> {
  return await SignatureModule.deleteKey(alias);
}
