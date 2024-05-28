const ethers = require('ethers');
const sss = require('shamir-secret-sharing');
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

function generateFunctionSelectorAndTypesFromFunctionSignature(functionSignature) {
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
  
  return {
    selector: ethers.id(canonincalFunctionSignature).substring(0, 10),
    types,
  };
}

function generateCallRequestDataFromAbi(
  abi,
  functionName,
  args = [],
) {
  const iface = new ethers.Interface(abi);
  const functionFragment = iface.getFunction(functionName);

  if (!functionFragment) {
    throw new Error(`Function "${functionName}" not found in ABI.`);
  }

  return iface.encodeFunctionData(functionFragment, args);
}

function generateCallRequestDataFromFunctionSignature(
  functionSignature,
  args = [],
) {
  const { selector, types } = generateFunctionSelectorAndTypesFromFunctionSignature(functionSignature);
  const encodedArgs = generateCalldataEncoding(types, args);

  return selector + encodedArgs.substring(2);
}

function generateCallRequest(
  target,
  value,
  nonce = generateRandomNonce(),
  data = '0x',
) {
  return [ target, value, nonce, data ];
}

function generateCalldataEncoding(
  types,
  values,
) {
  return ethers.AbiCoder.defaultAbiCoder().encode(types, values);
}

async function generateCallRequestSignature(
  wallet,
  callRequest,
  deadline,
  chainId,
) {
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

async function generateCallRequirements(
  wallet,
  target,
  abi,
  functionName,
  args,
  value,
  nonce,
  deadline,
  chainId,
) {
  const callData = abi
    ? generateCallRequestDataFromAbi(abi, functionName, args)
    : functionName 
      ? generateCallRequestDataFromFunctionSignature(functionName, args) 
      : '0x';

  const callRequest = generateCallRequest(target, value, nonce, callData);

  const signature = await generateCallRequestSignature(wallet, callRequest, deadline, chainId);

  return { callRequest, signature, deadline, chainId };
}

async function generateMulticallSignature(
  wallet,
  callRequests,
  deadline,
  chainId,
) {
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

async function generateMulticallRequirements(
  wallet,
  targets,
  abis,
  functionNames,
  args,
  values,
  nonces,
  deadline,
  chainId,
) {
  const callRequests = targets.map((target, i) => {
    const abi = abis[i];
    const functionName = functionNames[i];
    const callData = abi
      ? generateCallRequestDataFromAbi(abi, functionName, args[i])
      : functionName 
        ? generateCallRequestDataFromFunctionSignature(functionName, args[i])
        : '0x';

    return generateCallRequest(target, values[i], nonces[i], callData);
  });

  const signature = await generateMulticallSignature(wallet, callRequests, deadline, chainId);

  return { callRequests, signature, deadline, chainId };
}

async function generateScaCreationProofSignature(wallet) {
  return wallet.signMessage(SCA_CREATION_PROOF_MESSAGE);
}

async function generateNonceSignature(wallet, nonceBytes = 32) {
  const nonce = generateRandomNonce(nonceBytes);
  const signature = await wallet.signMessage(nonce);

  return { nonce, signature };
}

function generateSessionRequestTuple(sessionRequest = {}) {
  const transformSelectors = s => !s.startsWith('0x') ? generateFunctionSelectorAndTypesFromFunctionSignature(s).selector : s;

  return [
    sessionRequest.nativeAllowance || '0',
    (sessionRequest.contractFunctionSelectors || []).map(o => [ o.address, o.functionSelectors.map(transformSelectors) ]),
    (sessionRequest.erc20Allowances || []).map(o => [ o.address, o.allowance ]),
    (sessionRequest.erc721Allowances || []).map(o => [ o.address, o.approveAll, o.tokenIds || [] ]),
    (sessionRequest.erc1155Allowances || []).map(o => [ o.address, o.approveAll, o.tokenIds || [], o.allowances || [] ]),
  ];
}

async function generateSessionSignature(
  wallet,
  callerAddress,
  sessionRequest,
  expiresAt,
  nonce,
  deadline,
  chainId,
) {
  const encodedSessionRequest = generateCalldataEncoding(
    [
      'address',
      'tuple(' +
        'uint256, ' +
        'tuple(address, bytes4[])[], ' +
        'tuple(address, uint256)[], ' +
        'tuple(address, bool, uint256[])[], ' +
        'tuple(address, bool, uint256[], uint256[])[]' +
      ')',
      'uint256',
      'uint256',
      'uint256',
      'uint256',
    ],
    [
      callerAddress,
      generateSessionRequestTuple(sessionRequest),
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

async function generateAuthority() {
  const wallet = generateRandomWallet();
  const salt = generateRandomSalt();
  const authorityAddress = wallet.address;
  const authorityShards = await pkSplit(wallet.privateKey);
  const authorityProofSignature = await generateScaCreationProofSignature(wallet);

  return {
    salt,
    authorityAddress,
    authorityShards,
    authorityProofSignature,
  };
}

async function generateUser(
  username,
  email,
) {
  if (!username) {
    throw new Error('username and password must be provided.');
  }

  const authority = await generateAuthority();

  return {
    username,
    email,
    salt: authority.salt,
    authorityAddress: authority.authorityAddress,
    authorityShards: authority.authorityShards,
    authorityProofSignature: authority.authorityProofSignature,
  };
}

async function generateWalletFromHexShards(hexShards) {
  return new ethers.Wallet(await pkCombine(hexShards));
}

function generateWalletFromMnemonic(walletCredentials) {
  return ethers.Wallet.fromPhrase(walletCredentials.mnemonic);
}

async function getWalletCredentials(wallet) {
  return {
    address: wallet.address,
    privateKey: wallet.privateKey,
    mnemonic: wallet.mnemonic ? wallet.mnemonic.phrase : undefined,
  };
}

async function unshardWallet(walletHexShards) {
  const uint8ArrayShards = walletHexShards.map(hexShard => hexToUint8Array(hexShard));

  const walletCredentials = JSON.parse(uint8ArrayToString(await sss.combine(uint8ArrayShards)));

  return generateWalletFromMnemonic(walletCredentials);
}

async function shardWallet(wallet) {
  const walletCredentials = await getWalletCredentials(wallet);
  const walletCredentialsJson = JSON.stringify(walletCredentials);
  const shards = await sss.split(stringToUint8Array(walletCredentialsJson), 3, 2);

  return {
    localHexShard: uint8ArrayToHex(shards[0]),
    hyplayHexShard: uint8ArrayToHex(shards[1]),
    enclaveHexShard: uint8ArrayToHex(shards[2]),
  };
}


function toWei(etherString) {
  return ethers.parseEther(etherString);
}

function toEther(weiString) {
  return ethers.formatUnits(weiString);
}

async function toSha256(string) {
  const encoder = new TextEncoder();
  const data = encoder.encode(string);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

function hexToUint8Array(hexString) {
  if (hexString.startsWith('0x')) {
    hexString = hexString.slice(2);
  }

  return new Uint8Array(hexString.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function stringToUint8Array(string) {
  const uint8Array = new Uint8Array(string.length);

  for (let i = 0; i < string.length; i++) {
    uint8Array[i] = string.charCodeAt(i);
  }

  return uint8Array;
}

function uint8ArrayToString(uint8Array) {
  let string = '';
  
  for (let i = 0; i < uint8Array.length; i++) {
    string += String.fromCharCode(uint8Array[i]);
  }

  return string;
}

function uint8ArrayToHex(uint8Array) {
  return '0x' + Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/*
 * Export
 */

module.exports = {
  CHAIN_IDS,
  generateRandomNonce,
  generateRandomSalt,
  generateRandomWallet,
  generateFunctionSelectorAndTypesFromFunctionSignature,
  generateCallRequestDataFromAbi,
  generateCallRequestDataFromFunctionSignature,
  generateCallRequest,
  generateCalldataEncoding,
  generateCallRequestSignature,
  generateCallRequirements,
  generateMulticallSignature,
  generateMulticallRequirements,
  generateScaCreationProofSignature,
  generateNonceSignature,
  generateSessionRequestTuple,
  generateSessionSignature,
  generateAuthority,
  generateUser,
  generateWalletFromHexShards,
  generateWalletFromMnemonic,
  getWalletCredentials,
  shardWallet,
  unshardWallet,
  toWei,
  toEther,
  toSha256,
};
