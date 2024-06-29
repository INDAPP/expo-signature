import { generateEllipticCurveKeys } from "expo-signature";
import { PublicKey } from "expo-signature/SignatureModule.types";
import { useCallback, useState } from "react";
import { Button, StyleSheet, Text, View } from "react-native";

export default function App() {
  const [publicKey, setPublicKey] = useState<PublicKey>();

  const generateKeyPair = useCallback(async () => {
    const publicKey = await generateEllipticCurveKeys("test_ecc_key");
    setPublicKey(publicKey);
  }, []);

  return (
    <View style={styles.container}>
      <Text>{JSON.stringify(publicKey, null, 2)}</Text>
      <Button title="Generate Key Pair" onPress={generateKeyPair} />
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
