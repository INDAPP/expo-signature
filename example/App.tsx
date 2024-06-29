import {
  generateEllipticCurveKeys,
  getEllipticCurvePublicKey,
  isKeyPresentInKeychain,
  deleteKey,
} from "expo-signature";
import { PublicKey } from "expo-signature/SignatureModule.types";
import { useCallback, useState } from "react";
import { Button, StyleSheet, Text, View } from "react-native";

const keyTag = "test_ecc_key";

export default function App() {
  const [publicKey, setPublicKey] = useState<PublicKey | null>();
  const [isKeyPresent, setIsKeyPresent] = useState<boolean>();

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

  return (
    <View style={styles.container}>
      <Text>{JSON.stringify(publicKey, null, 2)}</Text>
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
      <Button title="Retrieve key" onPress={retrieveKey} />
      <Button title={`Check key: ${isKeyPresent}`} onPress={checkKey} />
      <Button title="Delete key" onPress={deleteKeyIfExists} />
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
