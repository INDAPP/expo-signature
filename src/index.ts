import SignatureModule from './SignatureModule';
import {
  KeySpec,
  SignatureAlgorithm,
  SignaturePrompt,
} from './SignatureModule.types';

export * from './SignatureModule.types';

export async function generateKeys<Algorithm extends SignatureAlgorithm>(
  keySpec: KeySpec<Algorithm>
): Promise<Uint8Array> {
  return await SignatureModule.generateKeys(keySpec);
}

export async function getPublicKey(alias: string): Promise<Uint8Array | null> {
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
  key: Uint8Array,
  algorithm: SignatureAlgorithm,
): Promise<boolean> {
  return await SignatureModule.verifyWithKey(data, signature, key, algorithm);
}
