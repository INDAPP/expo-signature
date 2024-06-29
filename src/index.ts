import { NativeModulesProxy, EventEmitter, Subscription } from 'expo-modules-core';

// Import the native module. On web, it will be resolved to SignatureModule.web.ts
// and on native platforms to SignatureModule.ts
import SignatureModule from './SignatureModule';
import SignatureModuleView from './SignatureModuleView';
import { ChangeEventPayload, SignatureModuleViewProps } from './SignatureModule.types';

// Get the native constant value.
export const PI = SignatureModule.PI;

export function hello(): string {
  return SignatureModule.hello();
}

export async function setValueAsync(value: string) {
  return await SignatureModule.setValueAsync(value);
}

const emitter = new EventEmitter(SignatureModule ?? NativeModulesProxy.SignatureModule);

export function addChangeListener(listener: (event: ChangeEventPayload) => void): Subscription {
  return emitter.addListener<ChangeEventPayload>('onChange', listener);
}

export { SignatureModuleView, SignatureModuleViewProps, ChangeEventPayload };
