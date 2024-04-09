import { Interface } from 'mocha';

declare module 'hychain-crypto-js' {
  import { InterfaceAbi, Wallet } from 'ethers';

  export type Ciphertext = string;
  export type PBKDF2Key = string;
  export type CallRequestData = string;
  export type CallRequest = [
    string, // target
    string, // value
    string, // nonce
    string, // data
  ];
  export type SessionRequest = {
    nativeAllowance?: string;
    contractFunctionSelectors?: {
      address: string,
      functionSelectors: string[]
    }[];
    erc20Allowances?: {
      address: string,
      allowance: string,
    }[];
    erc721Allowances?: {
      address: string,
      approveAll: boolean,
      tokenIds?: string[],
    }[];
    erc1155Allowances?: {
      address: string,
      approveAll: boolean,
      tokenIds?: string[],
      allowances?: string[],
    }[];
  };
  export type SessionRequestTuple = [
    string, // nativeAllowance
    [ string, string[] ][], // contractFunctionSelectors ( address, functionSelectors: bytes4[] )
    [ string, string ][], // erc20Allowances ( address, allowance: uint256 )
    [ string, boolean, string[] ][], // erc721Allowances ( address, approveAll: boolean, tokenIds: uint256[])
    [ string, boolean, string[], string[] ][], // erc1155Allowances ( address, approveAll: boolean, tokenIds: uint256[], allowances: uint256[] )
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
  
  export function generateCallRequestDataFromAbi(abi: InterfaceAbi, functionName: string, args?: any[]): CallRequestData;

  export function generateCallRequestDataFromFunctionSignature(functionSignature: string, args?: any[]): CallRequestData;

  export function generateCallRequest(target: string, value: string, nonce?: string, data?: CallRequestData): CallRequest;

  export function generateCalldataEncoding(abi: InterfaceAbi, values: any[]): string;

  export function generateCallRequestSignature(wallet: Wallet, callRequest: CallRequest, deadline: string, chainId: string): Promise<string>;

  export function generateCallRequestsSignature(wallet: Wallet, callRequest: CallRequest[], deadline: string, chainId: string): Promise<string>;

  export function generateScaCreationProofSignature(wallet: Wallet): Promise<string>;

  export function generateNonceSignature(wallet: Wallet, nonceBytes?: string): Promise<{
      nonce: string;
      signature: string;
  }>;

  export function generateSessionRequestTuple(sessionRequest: SessionRequest): SessionRequestTuple;

  export function generateSessionSignature(wallet: Wallet, callerAddress: string, sessionRequest: SessionRequest, expiresAt: string, nonce: string, deadline: string, chainId: string): Promise<string>;

  export function generateAuthority(password: string): Promise<{
      salt: string;
      authorityAddress: string;
      authorityCiphertext: Ciphertext;
      authorityProofSignature: string;
  }>;

  export function generateBackupCode(): string;

  export function generateBackupQuestions(): string[];

  export function generateUser(username: string, password: string, email?: string): Promise<{
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

  export function toSha256(string: string): Promise<string>;
}
