declare module 'hychain-crypto-js' {
  import { Wallet } from 'ethers';

  export const CHAIN_IDS: {
      HYCHAIN: number;
      HYCHAINTESTNET: number;
      LOCAL: number;
  };

  export function aesEncryptWallet(wallet: Wallet, password: string, salt: string): Promise<string>;
  
  export function aesDecryptWallet(ciphertext: string, password: string, salt: string): Promise<Wallet>;
  
  export function generateRandomSalt(): string;
  
  export function generateRandomWallet(): Wallet;
  
  export function generateCallRequestData(functionName: string, abi: any[], args: any[]): string;

  export function generateCallRequest(target: string, value: string, data?: string): {
      target: string;
      value: string;
      nonce: string;
      data: string;
  };

  export function generateCalldataEncoding(abi: any[], values: any[]): string;

  export function generateCallRequestSignature(wallet: Wallet, callRequest: {
      target: string;
      value: string;
      nonce: string;
      data: string;
  }, chainId: number): Promise<string>;

  export function generateScaCreationProofSignature(wallet: Wallet): Promise<string>;

  export function generateNonceSignature(wallet: Wallet, nonceBytes?: number): Promise<{
      nonce: string;
      signature: string;
  }>;

  export function generateAuthority(password: string): Promise<{
      salt: string;
      authorityAddress: string;
      authorityCiphertext: string;
      authorityProofSignature: string;
  }>;

  export function generateUser(username: string, email: string, password: string): Promise<{
      username: string;
      email: string;
      salt: string;
      authorityAddress: string;
      authorityCiphertext: string;
      authorityProofSignature: string;
  }>;

  export function getWalletCredentials(wallet: Wallet): {
      address: string;
      privateKey: string;
      mnemonic: string;
  };

  export function toWei(etherString: string): string;

  export function toEther(weiString: string): string;
}
