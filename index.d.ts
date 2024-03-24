declare module 'hychain-crypto-js' {
  import { Wallet } from 'ethers';

  export type Ciphertext = string;
  export type PBKDF2Key = string;
  export type CallRequestData = string;
  export type CallRequest = [
    string, // target
    string, // value
    string, // nonce
    string, // data
  ];
  export type WalletCredentials = {
    address: string;
    privateKey: string;
    mnemonic: string;
  }

  export const CHAIN_IDS: {
      HYCHAIN: number;
      HYCHAINTESTNET: number;
      LOCAL: number;
  };

  export function aesEncrypt(plaintext: string, key: PBKDF2Key): Promise<Ciphertext>;
  
  export function aesDecrypt(ciphertext: Ciphertext, key: PBKDF2Key): Promise<string>;

  export function aesEncryptWalletWithPassword(wallet: Wallet, password: string, salt: string): Promise<Ciphertext>;
  
  export function aesDecryptWalletWithPassword(ciphertext: Ciphertext, password: string, salt: string): Promise<Wallet>;
  
  export function aesEncryptWalletWithBackupCode(wallet: Wallet, code: string, salt: string): Promise<Ciphertext>;

  export function aesDecryptWalletWithBackupCode(ciphertext: Ciphertext, code: string, salt: string): Promise<Wallet>;

  export function aesEncryptWalletWithBackupQuestionAnswers(wallet: Wallet, answers: string[], salt: string): Promise<Ciphertext>;

  export function aesDecryptWalletWithBackupQuestionAnswers(ciphertext: Ciphertext, answers: string[], salt: string): Promise<Wallet>;

  export function pbkdf2(password: string, salt: string): Promise<PBKDF2Key>;

  export function generateRandomNonce(): string;

  export function generateRandomSalt(): string;
  
  export function generateRandomWallet(): Wallet;
  
  export function generateCallRequestDataFromAbi(abi: any[], functionName: string, args: any[]): CallRequestData;

  export function generateCallRequestDataFromFunctionSignature(functionSignature: string, args: any[]): CallRequestData;

  export function generateCallRequest(target: string, value: string, nonce?: string, data?: CallRequestData): CallRequest;

  export function generateCalldataEncoding(abi: any[], values: any[]): string;

  export function generateCallRequestSignature(wallet: Wallet, callRequest: CallRequest, deadline: number, chainId: number): Promise<string>;

  export function generateCallRequestsSignature(wallet: Wallet, callRequest: CallRequest[], deadline: number, chainId: number): Promise<string>;

  export function generateScaCreationProofSignature(wallet: Wallet): Promise<string>;

  export function generateNonceSignature(wallet: Wallet, nonceBytes?: number): Promise<{
      nonce: string;
      signature: string;
  }>;

  export function generateSessionSignature(wallet: Wallet, callerAddress: address, sessionRequest: SessionRequest, expiresAt: number, nonce: number, deadline: number, chainId: number): Promise<string>;

  export function generateAuthority(password: string): Promise<{
      salt: string;
      authorityAddress: string;
      authorityCiphertext: Ciphertext;
      authorityProofSignature: string;
  }>;

  export function generateBackupCode(): string;

  export function generateBackupQuestions(): string[];

  export function generateUser(username: string, email: string, password: string): Promise<{
      username: string;
      email: string;
      salt: string;
      authorityAddress: string;
      authorityCiphertext: Ciphertext;
      authorityProofSignature: string;
  }>;

  export function getWallet(walletCredentials: WalletCredentials): Wallet;

  export function getWalletCredentials(wallet: Wallet): WalletCredentials;

  export function toWei(etherString: string): string;

  export function toEther(weiString: string): string;
}
