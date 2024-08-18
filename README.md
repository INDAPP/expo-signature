# Expo Signature

`expo-signature` provides useful tools for digital signature on Android and iOS.

## API documentation

### Usage

```ts
import * as Signature from 'expo-signature';

const keyAlias = 'my_key_alias';

const encoder = new TextEncoder();
const data = encoder.encode('Data to sign');
```

#### Generate Key Pair

```ts
const keySpec: KeySpec = {
  alias: keyAlias,
  algorithm: 'EC', // or 'RSA'
  size: 256, // or 2048 for 'RSA'
};

const publicKey: PublicKey = await Signature.generateKeys(alias);
```

#### Retrieve an existing Public Key

```ts
const publicKey: PublicKey | null = await Signature.getPublicKey(alias);
```

#### Check for key presence

```ts
const keyExists: boolean = await Signature.isKeyPresentInKeychain(alias);
```

#### Delete Key Pair

```ts
const deleted: boolean = await Signature.deleteKey(alias);
```

#### Sign data

```ts
const info: SignaturePrompt = {
  title: 'User authentication',
  subtitle: 'Use biometry authentication to sign data',
  cancel: 'Cancel authentication',
};

const signature: Uint8Array = await Signature.signData(data, alias, info);
```

#### Verify data with key alias

```ts
const isValid: boolean = await Signature.verifyData(data, signature, alias);
```

#### Verify with Public Key

```ts
const publicKey: ECPublicKey = {
  x: '1234567890...',
  y: '0987654321...',
};

const isValid: boolean = await Signature.verifyWithKey(data, signature, publicKey);
```

### Example

Check the [example app](example/) for a full API usage.

## Installation in managed Expo projects

For [managed](https://docs.expo.dev/archive/managed-vs-bare/) Expo projects, please follow the installation instructions in the [API documentation for the latest stable release](#api-documentation). If you follow the link and there is no documentation available then this library is not yet usable within managed projects &mdash; it is likely to be included in an upcoming Expo SDK release.

## Installation in bare React Native projects

For bare React Native projects, you must ensure that you have [installed and configured the `expo` package](https://docs.expo.dev/bare/installing-expo-modules/) before continuing.

### Add the package to your npm dependencies

```
npm install expo-signature
```

### Configure for iOS

Add `NSFaceIDUsageDescription` key to your `Info.plist`:

```xml
<key>NSFaceIDUsageDescription</key>
<string>Allow $(PRODUCT_NAME) to use FaceID</string>
```

Run `npx pod-install` after installing the npm package.

### Configure for Android

No additional set up necessary.

This module requires permissions to access the biometric data for authentication purposes. The `USE_BIOMETRIC` and `USE_FINGERPRINT` permissions are automatically added.

```xml
<!-- Added permissions -->
<uses-permission android:name="android.permission.USE_BIOMETRIC" />
<uses-permission android:name="android.permission.USE_FINGERPRINT" />
```

### Config Plugin

> This plugin is applied automatically in EAS Build, only add the config plugin if you want to pass in extra properties.

After installing this npm package, add the [config plugin](https://docs.expo.dev/config-plugins/introduction) to the [`plugins`](https://docs.expo.io/versions/latest/config/app/#plugins) array of your `app.json` or `app.config.js`:

```json
{
  "expo": {
    "plugins": [
      [
        "expo-signature",
        {
          "faceIDPermission": "Allow $(PRODUCT_NAME) to use Face ID."
        }
      ]
    ]
  }
}
```

> Running `npx expo prebuild` will generate the [native project locally](https://docs.expo.dev/workflow/customizing/) with the applied changes in your iOS `Info.plist` file.

# Contributing

Contributions are very welcome! Please refer to guidelines described in the [contributing guide](https://github.com/expo/expo#contributing).
