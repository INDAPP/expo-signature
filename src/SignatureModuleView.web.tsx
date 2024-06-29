import * as React from 'react';

import { SignatureModuleViewProps } from './SignatureModule.types';

export default function SignatureModuleView(props: SignatureModuleViewProps) {
  return (
    <div>
      <span>{props.name}</span>
    </div>
  );
}
