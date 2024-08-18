import * as Clipboard from 'expo-clipboard';
import {
  isKeyPresentInKeychain,
  deleteKey,
  signData,
  verifyData,
  verifyWithKey,
  generateKeys,
  getPublicKey,
} from 'expo-signature';
import { ECPublicKey, RSAPublicKey } from 'expo-signature/SignatureModule.types';
import { useCallback, useMemo, useState } from 'react';
import { Button, StyleSheet, Text, View } from 'react-native';

const keyTag = 'test_ecc_key';

const data = stringToUint8Array('Hello World!');

export default function App() {
  const [publicKey, setPublicKey] = useState<ECPublicKey | RSAPublicKey | null>();
  const [isKeyPresent, setIsKeyPresent] = useState<boolean>();
  const [signedData, setSignedData] = useState<Uint8Array>();
  const [verified, setVerified] = useState<boolean>();

  const generateKeyPair = useCallback(async () => {
    const publicKey = await generateKeys({
      alias: keyTag,
      algorithm: 'RSA',
      size: 2048,
    });
    setPublicKey(publicKey);
  }, []);

  const retrieveKey = useCallback(async () => {
    const publicKey = await getPublicKey(keyTag);
    setPublicKey(publicKey);
  }, []);

  const checkKey = useCallback(async () => {
    const isPresent = await isKeyPresentInKeychain(keyTag);
    setIsKeyPresent(isPresent);
  }, []);

  const deleteKeyIfExists = useCallback(async () => {
    await deleteKey(keyTag);
  }, []);

  const sign = useCallback(async () => {
    const signedData = await signData(data, keyTag, {
      title: 'Sign',
      subtitle: 'Authenticate to sign data',
      cancel: 'Cancel',
    });
    setSignedData(signedData);
  }, []);

  const verify = useCallback(async () => {
    if (!signedData) {
      setVerified(undefined);
      return;
    }
    const verified = await verifyData(data, signedData, keyTag);
    setVerified(verified);
  }, [signedData]);

  const verifyWithoutKeychain = useCallback(async () => {
    if (!signedData || !publicKey) {
      setVerified(undefined);
      return;
    }
    const verified = await verifyWithKey(data, signedData, publicKey);
    setVerified(verified);
  }, [signedData, publicKey]);

  const copyPublicKey = useCallback(() => {
    Clipboard.setStringAsync(JSON.stringify(publicKey));
  }, [publicKey]);

  const copySignature = useCallback(() => {
    if (!signedData) {
      return;
    }
    const stringData = uInt8ArrayToHexString(signedData);
    Clipboard.setStringAsync(stringData);
  }, [signedData]);

  const publicKeyContent = useMemo(() => {
    if (!publicKey) {
      return null;
    }
    return `Public key:\n${JSON.stringify(publicKey, null, 2)}`;
  }, [publicKey]);

  const signatureContent = useMemo(() => {
    if (!signedData) {
      return null;
    }
    return `Signature:\n${uInt8ArrayToHexString(signedData)}`;
  }, [signedData]);

  return (
    <View style={styles.container}>
      <Text>{publicKeyContent}</Text>
      {publicKey && <Button title="Copy key" onPress={copyPublicKey} />}
      <Text>{signatureContent}</Text>
      {signedData && <Button title="Copy signature" onPress={copySignature} />}
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
      <Button title="Retrieve key" onPress={retrieveKey} />
      <Button title={`Check key: ${isKeyPresent}`} onPress={checkKey} />
      <Button title="Delete key" onPress={deleteKeyIfExists} />
      <Button title="Sign data" onPress={sign} />
      <Button title="Verify data" onPress={verify} />
      <Button title="Verify with key" onPress={verifyWithoutKeychain} />
      <Text>{verified ? 'Data verified succesfully' : 'Not yet verified'}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
    padding: 16,
  },
});

function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

function uInt8ArrayToHexString(data: Uint8Array): string {
  return Array.from(data)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join(':');
}
