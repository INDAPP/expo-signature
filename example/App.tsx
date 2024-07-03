import {
  generateEllipticCurveKeys,
  getEllipticCurvePublicKey,
  isKeyPresentInKeychain,
  deleteKey,
  signData,
} from "expo-signature";
import { PublicKey } from "expo-signature/SignatureModule.types";
import { useCallback, useState } from "react";
import { Button, StyleSheet, Text, View } from "react-native";

const keyTag = "test_ecc_key";

export default function App() {
  const [publicKey, setPublicKey] = useState<PublicKey | null>();
  const [isKeyPresent, setIsKeyPresent] = useState<boolean>();
  const [signedData, setSignedData] = useState<string>();

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
    const data = stringToUint8Array("Hello World!");
    try {
      const signedData = await signData(data, {
        alias: keyTag,
        title: "Sign",
        subtitle: "Authenticate to sign data",
        cancel: "Cancel",
      });
      setSignedData(uInt8ArrayToHexString(signedData));
    } catch (e) {
      setSignedData(JSON.stringify(e));
    }
  }, []);

  return (
    <View style={styles.container}>
      <Text>{JSON.stringify(publicKey, null, 2)}</Text>
      <Text>{signedData}</Text>
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
      <Button title="Retrieve key" onPress={retrieveKey} />
      <Button title={`Check key: ${isKeyPresent}`} onPress={checkKey} />
      <Button title="Delete key" onPress={deleteKeyIfExists} />
      <Button title="Sign data" onPress={sign} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#fff",
    alignItems: "center",
    justifyContent: "center",
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
