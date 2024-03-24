const ethers = require('ethers');
const crypto = globalThis.crypto;

// must be signed as uint8array bytes, hence .getBytes()
const SCA_CREATION_PROOF_MESSAGE = ethers.getBytes(ethers.id('Approve HYPLAY wallet creation'));

const CHAIN_IDS = {
  HYCHAIN: 2911,
  HYCHAINTESTNET: 29112,
  LOCAL: 31337,
};

/*
 * Public
 */

async function aesEncrypt(plaintext, pbkdf2Key) {
  const keyBuffer = new Uint8Array(pbkdf2Key.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBuffer = new TextEncoder().encode(plaintext);

  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, [ 'encrypt' ]);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintextBuffer);

  return Array.from(new Uint8Array([ ...iv, ...new Uint8Array(ciphertext) ])).map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function aesDecrypt(ciphertext, pbkdf2Key) {
  const keyBuffer = new Uint8Array(pbkdf2Key.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
  const ciphertextBuffer = new Uint8Array(ciphertext.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

  const iv = ciphertextBuffer.subarray(0, 12);
  const actualCiphertext = ciphertextBuffer.subarray(12);

  const cryptoKey = await crypto.subtle.importKey('raw', keyBuffer, 'AES-GCM', false, [ 'decrypt' ]);
  const plaintextBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, actualCiphertext);

  return new TextDecoder().decode(plaintextBuffer);
}

async function aesEncryptWalletWithPassword(wallet, password, salt) {
  try {
    const key = await pbkdf2(password, salt);

    return await aesEncrypt(JSON.stringify(getWalletCredentials(wallet)), key);
  } catch (error) {
    throw new Error('Wallet could not be encrypted.');
  }
}

async function aesDecryptWalletWithPassword(ciphertext, password, salt) {
  try {
    const key = await pbkdf2(password, salt);
    const walletCredentials = JSON.parse(await aesDecrypt(ciphertext, key));

    return getWallet(walletCredentials);
  } catch (error) {
    throw new Error('Wallet could not be decrypted.');
  }
}

async function aesEncryptWalletWithBackupCode(wallet, code, salt) {
  if (code.length < 10) { throw new Error('code must be at least 10 characters.'); }

  try {
    const key = await pbkdf2(code, salt);

    return await aesEncrypt(JSON.stringify(getWalletCredentials(wallet)), key);
  } catch (error) {
    throw new Error('Wallet could not be encrypted.');
  }
}

async function aesDecryptWalletWithBackupCode(ciphertext, code, salt) {
  try {
    const key = await pbkdf2(code, salt);
    const walletCredentials = JSON.parse(await aesDecrypt(ciphertext, key));

    return getWallet(walletCredentials);
  } catch (error) {
    throw new Error('Wallet could not be decrypted.');
  }
}

async function aesEncryptWalletWithBackupQuestionAnswers(wallet, answers, salt) {
  try {
    const key = await pbkdf2(answers.join(','), salt);

    return await aesEncrypt(JSON.stringify(getWalletCredentials(wallet)), key);
  } catch (error) {
    throw new Error('Wallet could not be encrypted.');
  }
}

async function aesDecryptWalletWithBackupQuestionAnswers(ciphertext, answers, salt) {
  try {
    const key = await pbkdf2(answers.join(','), salt);
    const walletCredentials = JSON.parse(await aesDecrypt(ciphertext, key));

    return getWallet(walletCredentials);
  } catch (error) {
    throw new Error('Wallet could not be decrypted.');
  }
}

async function pbkdf2(password, salt) {
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

function generateRandomNonce(nonceBytes = 32) {
  return ethers.hexlify(ethers.randomBytes(nonceBytes));
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

function generateCallRequestDataFromAbi(abi, functionName, args) {
  const iface = new ethers.Interface(abi);
  const functionFragment = iface.getFunction(functionName);

  if (!functionFragment) {
    throw new Error('Function not found in ABI.');
  }

  return iface.encodeFunctionData(functionFragment, args);
}

function generateCallRequestDataFromFunctionSignature(functionSignature, args) {
  const functionName = functionSignature.split('(')[0];
  const parametersList = functionSignature.slice(functionSignature.indexOf('(') + 1, functionSignature.lastIndexOf(')'));

  let types = [];
  let depth = 0;
  let currentType = '';
  for (let char of parametersList) {
    if (char === '(') depth++; // Entering a tuple or nested tuple
    else if (char === ')') depth--; // Exiting a tuple or nested tuple

    if (depth === 0 && char === ',') { // At root level, commas separate types
      types.push(currentType.trim());
      currentType = '';
    } else {
      currentType += char;
    }
  }
  if (currentType) types.push(currentType.trim()); // Add the last type

  // Simplify the parsing, extracting only the base types without parameter names
  types = types.map(type => type.lastIndexOf(' ') !== -1 ? type.slice(0, type.lastIndexOf(' ')) : type);

  const canonincalFunctionSignature = `${functionName}(${types.join(',')})`;
  const functionSelector = ethers.id(canonincalFunctionSignature).substring(0, 10);
  const encodedArgs = generateCalldataEncoding(types, args);

  return functionSelector + encodedArgs.substring(2);
}

function generateCallRequest(target, value, nonce = generateRandomNonce(), data = '0x') {
  return [ target, value, nonce, data ];
}

function generateCalldataEncoding(types, values) {
  return ethers.AbiCoder.defaultAbiCoder().encode(types, values);
}

async function generateCallRequestSignature(wallet, callRequest, deadline, chainId) {
  const encodedCallRequest = generateCalldataEncoding(
    [
      'tuple(address, uint256, uint256, bytes)',
      'uint256',
      'uint256',
    ],
    [
      callRequest,
      deadline,
      chainId,
    ],
  );

  return await wallet.signMessage(
    ethers.getBytes(ethers.keccak256(encodedCallRequest)),
  );
}

async function generateCallRequestsSignature(wallet, callRequests, deadline, chainId) {
  const encodedCallRequests = generateCalldataEncoding(
    [
      'tuple(address, uint256, uint256, bytes)[]',
      'uint256',
      'uint256',
    ],
    [
      callRequests,
      deadline,
      chainId,
    ],
  );

  return await wallet.signMessage(
    ethers.getBytes(ethers.keccak256(encodedCallRequests)),
  );
}

async function generateScaCreationProofSignature(wallet) {
  return wallet.signMessage(SCA_CREATION_PROOF_MESSAGE);
}

async function generateNonceSignature(wallet, nonceBytes = 32) {
  const nonce = generateRandomNonce(nonceBytes);
  const signature = await wallet.signMessage(nonce);

  return { nonce, signature };
}

async function generateSessionSignature(wallet, callerAddress, sessionRequest, expiresAt, nonce, deadline, chainId) {
  const encodedSessionRequest = generateCalldataEncoding(
    [
      'address',
      'tuple(uint256, tuple(address, bytes4[])[], tuple(address, uint256)[], tuple(address, bool, uint256[])[], tuple(address, bool, uint256[], uint256[])[])',
      'uint256',
      'uint256',
      'uint256',
      'uint256',
    ],
    [
      callerAddress,
      sessionRequest,
      expiresAt,
      nonce,
      deadline,
      chainId,
    ],
  );

  return wallet.signMessage(
    ethers.getBytes(ethers.keccak256(encodedSessionRequest)),
  );
}

async function generateAuthority(password) {
  if (!password) {
    throw new Error('password must be provided.');
  }

  const wallet = generateRandomWallet();
  const salt = generateRandomSalt();
  const authorityAddress = wallet.address;
  const authorityCiphertext = await aesEncryptWalletWithPassword(wallet, password, salt);
  const authorityProofSignature = await generateScaCreationProofSignature(wallet);

  return {
    salt,
    authorityAddress,
    authorityCiphertext,
    authorityProofSignature,
  };
}

function generateBackupCode() {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+=';

  let password = '';
  
  for (let i = 0; i < 10; i++) {
    const randomIndex = Math.floor(Math.random() * charset.length);
    password += charset[randomIndex];
  }
  
  return password;
}

function generateBackupQuestions() {
  return [
    'What was the make and model of your first car?',
    'What is the name of the street where you grew up?',
    'What was the name of your first pet?',
    'What was the first concert you attended?',
    'What is the middle name of your oldest sibling?',
    'In what city or town did your parents meet?',
    'What was the name of your favorite teacher in school?',
    'What was your dream job as a child?',
    'What is the name of the place your wedding reception was held?',
    'What is the first name of the person you went to your first dance with?'
  ];
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

function getWallet(walletCredentials) {
  return ethers.Wallet.fromPhrase(walletCredentials.mnemonic);
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
 * Export
 */

module.exports = {
  CHAIN_IDS,
  aesEncrypt,
  aesDecrypt,
  aesEncryptWalletWithPassword,
  aesDecryptWalletWithPassword,
  aesEncryptWalletWithBackupCode,
  aesDecryptWalletWithBackupCode,
  aesEncryptWalletWithBackupQuestionAnswers,
  aesDecryptWalletWithBackupQuestionAnswers,
  pbkdf2,
  generateRandomNonce,
  generateRandomSalt,
  generateRandomWallet,
  generateCallRequestDataFromAbi,
  generateCallRequestDataFromFunctionSignature,
  generateCallRequest,
  generateCalldataEncoding,
  generateCallRequestSignature,
  generateCallRequestsSignature,
  generateScaCreationProofSignature,
  generateNonceSignature,
  generateSessionSignature,
  generateAuthority,
  generateBackupCode,
  generateBackupQuestions,
  generateUser,
  getWallet,
  getWalletCredentials,
  toWei,
  toEther,
};
