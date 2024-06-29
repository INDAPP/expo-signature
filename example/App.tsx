import { StyleSheet, Text, View } from 'react-native';

import * as SignatureModule from 'expo-signature';

export default function App() {
  return (
    <View style={styles.container}>
      <Text>{SignatureModule.hello()}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#fff',
    alignItems: 'center',
    justifyContent: 'center',
  },
});
