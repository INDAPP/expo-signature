import SignatureModule from './SignatureModule';
import {
  ECPublicKey,
  KeySpec,
  PublicKey,
  RSAPublicKey,
  SignatureAlgorithm,
  SignaturePrompt,
} from './SignatureModule.types';

export async function generateKeys<Algorithm extends SignatureAlgorithm>(
  keySpec: KeySpec<Algorithm>
): Promise<Algorithm extends 'EC' ? ECPublicKey : Algorithm extends 'RSA' ? RSAPublicKey : never> {
  return await SignatureModule.generateKeys(keySpec);
}

export async function getPublicKey(alias: string): Promise<PublicKey | null> {
  return await SignatureModule.getPublicKey(alias);
}

export async function isKeyPresentInKeychain(alias: string): Promise<boolean> {
  return await SignatureModule.isKeyPresentInKeychain(alias);
}

export async function deleteKey(alias: string): Promise<boolean> {
  return await SignatureModule.deleteKey(alias);
}

export async function signData(
  data: Uint8Array,
  alias: string,
  info: SignaturePrompt
): Promise<Uint8Array> {
  return await SignatureModule.sign(data, alias, info);
}

export async function verifyData(
  data: Uint8Array,
  signature: Uint8Array,
  alias: string
): Promise<boolean> {
  return await SignatureModule.verify(data, signature, alias);
}

export async function verifyWithKey(
  data: Uint8Array,
  signature: Uint8Array,
  key: PublicKey
): Promise<boolean> {
  return await SignatureModule.verifyWithKey(data, signature, key);
}
