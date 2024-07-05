import {
  generateEllipticCurveKeys,
  getEllipticCurvePublicKey,
  isKeyPresentInKeychain,
  deleteKey,
  signData,
  verifyData,
} from "expo-signature";
import { PublicKey } from "expo-signature/SignatureModule.types";
import { useCallback, useState } from "react";
import { Button, StyleSheet, Text, View } from "react-native";

const keyTag = "test_ecc_key";

const data = stringToUint8Array("Hello World!");

export default function App() {
  const [publicKey, setPublicKey] = useState<PublicKey | null>();
  const [isKeyPresent, setIsKeyPresent] = useState<boolean>();
  const [signedData, setSignedData] = useState<Uint8Array>();
  const [verified, setVerified] = useState<boolean>();

  const generateKeyPair = useCallback(async () => {
    const publicKey = await generateEllipticCurveKeys(keyTag);
    setPublicKey(publicKey);
  }, []);

  const retrieveKey = useCallback(async () => {
    const publicKey = await getEllipticCurvePublicKey(keyTag);
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
    const signedData = await signData(data, {
      alias: keyTag,
      title: "Sign",
      subtitle: "Authenticate to sign data",
      cancel: "Cancel",
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
  }, [signData]);

  return (
    <View style={styles.container}>
      <Text>{JSON.stringify(publicKey, null, 2)}</Text>
      <Text>{signedData && uInt8ArrayToHexString(signedData)}</Text>
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
      <Button title="Retrieve key" onPress={retrieveKey} />
      <Button title={`Check key: ${isKeyPresent}`} onPress={checkKey} />
      <Button title="Delete key" onPress={deleteKeyIfExists} />
      <Button title="Sign data" onPress={sign} />
      <Button title="Verify data" onPress={verify} />
      <Text>{verified ? "Data verified succesfully" : "Not yet verified"}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
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
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join(":");
}
