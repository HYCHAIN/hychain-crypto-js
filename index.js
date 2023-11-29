const ethers = require('ethers');
const cryptoJS = require('crypto-js');
const { pbkdf2Sync } = require('pbkdf2');

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

function aesEncryptWallet(wallet, password, salt) {
  const key = _pbkdf2(password, salt);

  try {
    return _aesEncrypt(JSON.stringify(getWalletCredentials(wallet)), key);
  } catch (error) {
    throw new Error('Wallet could not be encrypted.');
  }
}

function aesDecryptWallet(ciphertext, password, salt) {
  const key = _pbkdf2(password, salt);

  try {
    const walletCredentials = JSON.parse(_aesDecrypt(ciphertext, key));

    return _getWallet(walletCredentials);
  } catch (error) {
    throw new Error('Wallet could not be decrypted.');
  }
}

function generateRandomSalt() {
  return cryptoJS.lib.WordArray.random(512 / 8).toString();
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

async function generateUser(username, email, phone, password) {
  if (!username && (!email || !phone) && !password) {
    throw new Error('username, and email or phone, and password must be provided.');
  }

  const wallet = generateRandomWallet();
  const salt = generateRandomSalt();
  const authorityAddress = wallet.address;
  const authorityCiphertext = aesEncryptWallet(wallet, password, salt);
  const authorityProofSignature = await generateScaCreationProofSignature(wallet);

  return {
    username,
    email,
    phone,
    salt,
    authorityAddress,
    authorityCiphertext,
    authorityProofSignature,
  }
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
  return ethers.formatUnits(weiString)
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

function _aesEncrypt(plaintext, key) {
  try {
    return cryptoJS.AES.encrypt(plaintext, key).toString();
  } catch (error) {
    throw new Error('Could not encrypt.');
  }
}

function _aesDecrypt(ciphertext, key) {
  try {
    return cryptoJS.AES.decrypt(ciphertext, key).toString(cryptoJS.enc.Utf8);
  } catch (error) {
    throw new Error('Could not decrypt');
  }
}

function _pbkdf2(password, salt) {
  return pbkdf2Sync(
    password,
    salt,
    210000, // iterations,
    32, // key length
    'sha512',
  ).toString('hex');
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
  generateUser,
  getWalletCredentials,
  toWei,
  toEther,
};
