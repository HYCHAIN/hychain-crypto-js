const ethers = require('ethers');
const crypto = globalThis.crypto;

// must be signed as uint8array bytes, hence .getBytes()
const SCA_CREATION_PROOF_MESSAGE = ethers.getBytes(ethers.id('Approve HYTOPIA wallet creation'));

const CHAIN_IDS = {
  HYTOPIA: 2911,
  HYTOPIATESTNET: 29112,
  LOCAL: 31337,
};

/*
 * Public
 */

async function aesEncryptWallet(wallet, password, salt) {
  try {
    const key = await _pbkdf2(password, salt);

    return await _aesEncrypt(JSON.stringify(getWalletCredentials(wallet)), key);
  } catch (error) {
    throw new Error('Wallet could not be encrypted.');
  }
}

async function aesDecryptWallet(ciphertext, password, salt) {
  try {
    const key = await _pbkdf2(password, salt);
    const walletCredentials = JSON.parse(await _aesDecrypt(ciphertext, key));

    return _getWallet(walletCredentials);
  } catch (error) {
    throw new Error('Wallet could not be decrypted.');
  }
}

function generateRandomSalt() {
  const array = new Uint8Array(64);
  crypto.getRandomValues(array);

  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

function generateRandomWallet() {
  return ethers.Wallet.createRandom({
    extraEntropy: Math.floor(10 * 6 * 2021 * Math.random()), // 10/6/2021 was original launch date!
  });
}

function generateCallRequestData(functionName, abi, args) {
  const functionSelector = ethers.id(functionName).substring(0, 10);
  const encodedArgs = generateCalldataEncoding(abi, args);

  return functionSelector + encodedArgs.substring(2);
}

function generateCallRequest(target, value, data) {
  const nonce = _generateNonce();

  return { target, value, nonce, data: data || '0x' };
}

function generateCalldataEncoding(abi, values) {
  return ethers.AbiCoder.defaultAbiCoder().encode(abi, values);
}

async function generateCallRequestSignature(wallet, callRequest, chainId) {
  const encodedCallRequest = generateCalldataEncoding(
    [
      'tuple(address target, uint256 value, uint256 nonce, bytes data)',
      'uint256',
    ],
    [
      callRequest,
      chainId,
    ],
  );

  return await wallet.signMessage(
    ethers.getBytes(ethers.keccak256(encodedCallRequest)),
  );
}

async function generateScaCreationProofSignature(wallet) {
  return wallet.signMessage(SCA_CREATION_PROOF_MESSAGE);
}

async function generateNonceSignature(wallet, nonceBytes = 32) {
  const nonce = _generateNonce(nonceBytes);
  const signature = await wallet.signMessage(nonce);

  return { nonce, signature };
}

async function generateAuthority(password) {
  if (!password) {
    throw new Error('password must be provided.');
  }

  const wallet = generateRandomWallet();
  const salt = generateRandomSalt();
  const authorityAddress = wallet.address;
  const authorityCiphertext = await aesEncryptWallet(wallet, password, salt);
  const authorityProofSignature = await generateScaCreationProofSignature(wallet);

  return {
    salt,
    authorityAddress,
    authorityCiphertext,
    authorityProofSignature,
  };
}

async function generateUser(username, email, password) {
  if (!username && !email && !password) {
    throw new Error('username, email and password must be provided.');
  }

  const authority = await generateAuthority(password);

  return {
    username,
    email,
    salt: authority.salt,
    authorityAddress: authority.authorityAddress,
    authorityCiphertext: authority.authorityCiphertext,
    authorityProofSignature: authority.authorityProofSignature,
  };
}

function getWalletCredentials(wallet) {
  return {
    address: wallet.address,
    privateKey: wallet.privateKey,
    mnemonic: wallet.mnemonic.phrase,
  };
}

function toWei(etherString) {
  return ethers.parseEther(etherString);
}

function toEther(weiString) {
  return ethers.formatUnits(weiString);
}

/*
 * Helpers
 */

function _getWallet(walletCredentials) {
  return ethers.Wallet.fromPhrase(walletCredentials.mnemonic);
}

function _generateNonce(nonceBytes = 32) {
  return ethers.hexlify(ethers.randomBytes(nonceBytes));
}

async function _aesEncrypt(plaintext, key) {
  const keyBuffer = new Uint8Array(key.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBuffer = new TextEncoder().encode(plaintext);

  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, [ 'encrypt' ]);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintextBuffer);

  return Array.from(new Uint8Array([ ...iv, ...new Uint8Array(ciphertext) ])).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function _aesDecrypt(ciphertext, key) {
  const keyBuffer = new Uint8Array(key.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const ciphertextBuffer = new Uint8Array(ciphertext.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

  const iv = ciphertextBuffer.subarray(0, 12);
  const actualCiphertext = ciphertextBuffer.subarray(12);

  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, [ 'decrypt' ]);
  const plaintextBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, actualCiphertext);

  return new TextDecoder().decode(plaintextBuffer);
}

async function _pbkdf2(password, salt) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    { name: 'PBKDF2' },
    false,
    [ 'deriveBits', 'deriveKey' ],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: new TextEncoder().encode(salt),
      iterations: 600000,
      hash: 'SHA-512',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 32 * 8 },
    true,
    [ 'encrypt', 'decrypt' ],
  );
  const keyBuffer = await crypto.subtle.exportKey('raw', key);

  return Array.from(new Uint8Array(keyBuffer)).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

/*
 * Export
 */

module.exports = {
  CHAIN_IDS,
  aesEncryptWallet,
  aesDecryptWallet,
  generateRandomSalt,
  generateRandomWallet,
  generateCallRequestData,
  generateCallRequest,
  generateCalldataEncoding,
  generateCallRequestSignature,
  generateScaCreationProofSignature,
  generateNonceSignature,
  generateAuthority,
  generateUser,
  getWalletCredentials,
  toWei,
  toEther,
};
