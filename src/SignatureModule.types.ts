export type SignatureAlgorithm = 'EC' | 'RSA';

export type KeySpec<Algorithm extends SignatureAlgorithm = SignatureAlgorithm> = {
  algorithm: Algorithm;
  alias: string;
  size: number;
};

export type ECPublicKey = {
  x: string;
  y: string;
};

export type RSAPublicKey = {
  n: string;
  e: string;
};

export type PublicKey = ECPublicKey | RSAPublicKey;

export type SignaturePrompt = {
  title?: string;
  subtitle?: string;
  cancel?: string;
};
