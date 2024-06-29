import { requireNativeViewManager } from 'expo-modules-core';
import * as React from 'react';

import { SignatureModuleViewProps } from './SignatureModule.types';

const NativeView: React.ComponentType<SignatureModuleViewProps> =
  requireNativeViewManager('SignatureModule');

export default function SignatureModuleView(props: SignatureModuleViewProps) {
  return <NativeView {...props} />;
}
