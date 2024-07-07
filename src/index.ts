import SignatureModule from "./SignatureModule";
import { PublicKey, SignatureInfo } from "./SignatureModule.types";

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

export async function signData(
  data: Uint8Array,
  info: SignatureInfo,
): Promise<Uint8Array> {
  return await SignatureModule.sign(data, info);
}

export async function verifyData(
  data: Uint8Array,
  signature: Uint8Array,
  alias: string,
): Promise<boolean> {
  return await SignatureModule.verify(data, signature, alias);
}

export async function addPublicKey(
  key: PublicKey,
  alias: string,
): Promise<void> {
  return await SignatureModule.addPublicKey(key, alias);
}
