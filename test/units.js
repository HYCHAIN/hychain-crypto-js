const lib = require('../');

const chai = require('chai');
chai.should();

describe('Unit Tests', () => {
  it('aesEncrypt(), aesDecrypt(), pbkdf2()', async () => {
    const plaintext = 'sometext';
    const passwordOrKeyMaterial = 'password';
    const pbkdf2Key = await lib.pbkdf2(passwordOrKeyMaterial, 'someSalt');
    const ciphertext = await lib.aesEncrypt(plaintext, pbkdf2Key);
    const decrypted = await lib.aesDecrypt(ciphertext, pbkdf2Key);

    decrypted.should.equal(plaintext);
  });

  it('aesEncryptWalletWithPasswordOrKeyMaterial(), aesDecryptWalletWithPasswordOrKeyMaterial()', async () => {
    const wallet = lib.generateRandomWallet();
    const passwordOrKeyMaterial = 'somepass';
    const salt = lib.generateRandomSalt();
    const ciphertext = await lib.aesEncryptWalletWithPasswordOrKeyMaterial(wallet, passwordOrKeyMaterial, salt);
    const decryptedWallet = await lib.aesDecryptWalletWithPasswordOrKeyMaterial(ciphertext, passwordOrKeyMaterial, salt);

    decryptedWallet.address.should.equal(wallet.address);
    decryptedWallet.mnemonic.phrase.should.equal(wallet.mnemonic.phrase);
  });

  it('aesEncryptWalletWithBackupCode(), aesDecryptWalletWithBackupCode()', async () => {
    const wallet = lib.generateRandomWallet();
    const backupCode = lib.generateBackupCode();
    const salt = lib.generateRandomSalt();
    const ciphertext = await lib.aesEncryptWalletWithBackupCode(wallet, backupCode, salt);
    const decryptedWallet = await lib.aesDecryptWalletWithBackupCode(ciphertext, backupCode, salt);

    decryptedWallet.address.should.equal(wallet.address);
    decryptedWallet.mnemonic.phrase.should.equal(wallet.mnemonic.phrase);
  });

  it('aesEncryptWalletWithBackupQuestionAnswers(), aesDecryptWalletWithBackupQuestionAnswers()', async () => {
    const wallet = lib.generateRandomWallet();
    const answers = [ '1994', 'Robert', 'Red' ];
    const salt = lib.generateRandomSalt();
    const ciphertext = await lib.aesEncryptWalletWithBackupQuestionAnswers(wallet, answers, salt);
    const decryptedWallet = await lib.aesDecryptWalletWithBackupQuestionAnswers(ciphertext, answers, salt);

    decryptedWallet.address.should.equal(wallet.address);
    decryptedWallet.mnemonic.phrase.should.equal(wallet.mnemonic.phrase);
  });
  
  it('generateRandomNonce()', async() => {
    const nonce = await lib.generateRandomNonce();

    nonce.should.be.a('string');
    nonce.length.should.equal(66);
  });

  it('generateRandomSalt()', () => {
    const salt = lib.generateRandomSalt();
    const salt2 = lib.generateRandomSalt();

    salt.length.should.equal(128);
    salt.should.not.equal(salt2);
  });

  it('generateRandomWallet()', () => {
    const wallet = lib.generateRandomWallet();
    const wallet2 = lib.generateRandomWallet();

    wallet.constructor.name.should.equal('HDNodeWallet');
    wallet.address.should.not.equal(wallet2.address);
  });

  it('generateFunctionSelectorAndTypesFromFunctionSignature()', () => {
    const { selector, types } = lib.generateFunctionSelectorAndTypesFromFunctionSignature('transfer(address,uint256)');

    selector.should.equal('0xa9059cbb');
    types.should.be.an('array');
    types[0].should.equal('address');
    types[1].should.equal('uint256');
  });

  it('generateCallRequestDataFromAbi()', () => {
    const abi = [
      {
        inputs: [
          {
            internalType: 'address',
            name: '_recipient',
            type: 'address',
          },
          {
            internalType: 'uint256',
            name: '_amount',
            type: 'uint256',
          },
        ],
        name: 'transfer',
        outputs: [],
        stateMutability: 'nonpayable',
        type: 'function',
      },
    ];

    const callRequestData = lib.generateCallRequestDataFromAbi(
      abi,
      'transfer',
      [ '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', 100 ],
    );
    
    callRequestData.should.equal('0xa9059cbb000000000000000000000000ccccb68e1a848cbdb5b60a974e07aae143ed40c30000000000000000000000000000000000000000000000000000000000000064');
  });

  it('generateCallRequestDataFromFunctionSignature()', () => {
    const callRequestData = lib.generateCallRequestDataFromFunctionSignature(
      'transfer(address,uint256)',
      [ '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', 100 ],
    );
    
    callRequestData.should.equal('0xa9059cbb000000000000000000000000ccccb68e1a848cbdb5b60a974e07aae143ed40c30000000000000000000000000000000000000000000000000000000000000064');
  });

  it('generateCallRequest()', () => {
    const callRequest = lib.generateCallRequest(
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
      lib.toWei('2.0'),
    );

    callRequest.should.be.an('array');
    callRequest[2].should.be.a('string'); // nonce
  });

  it('generateCreateRequest()', () => {
    const createRequest = lib.generateCreateRequest(
      '0x5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505',
      '0x0',
    );

    createRequest.should.be.an('array');
  });

  it('generateCreateRequestSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const createRequest = lib.generateCreateRequest(
      '0x5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505',
      '0x0',
    );
    const deadline = Math.floor(Date.now()/ 1000);
    const chainId = lib.CHAIN_IDS['HYCHAIN'];
    const createRequestSignature = await lib.generateCreateRequestSignature(wallet, createRequest, deadline, chainId);

    createRequestSignature.length.should.equal(132);
  });

  it('generateCalldataEncoding()', () => {
    const calldataEncoding = lib.generateCalldataEncoding(
      [ 'address', 'uint256'  ],
      [ '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', 251275 ],
    );

    calldataEncoding.should.equal('0x000000000000000000000000ccccb68e1a848cbdb5b60a974e07aae143ed40c3000000000000000000000000000000000000000000000000000000000003d58b');
  });

  it('generateCallRequestSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const callRequest = lib.generateCallRequest(
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
      lib.toWei('2.0'),
    );
    const deadline = Math.floor(Date.now()/ 1000);
    const chainId = lib.CHAIN_IDS['HYCHAIN'];
    const callRequestSignature = await lib.generateCallRequestSignature(wallet, callRequest, deadline, chainId);

    callRequestSignature.length.should.equal(132);
  });

  it('generateCallRequirements()', async () => {
    const wallet = lib.generateRandomWallet();
    const deadline = Math.floor(Date.now()/ 1000);
    const chainId = lib.CHAIN_IDS['HYCHAIN'];

    const callRequirements = await lib.generateCallRequirements(
      wallet, 
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', 
      null, 
      null, 
      null, 
      lib.toWei('2.0'), 
      '3',
      deadline, 
      chainId,
    );

    callRequirements.should.be.an('object');
    callRequirements.callRequest.should.be.an('array');
    callRequirements.signature.should.be.a('string');
    callRequirements.deadline.should.be.a('number');
    callRequirements.chainId.should.be.a('number');
  });

  it('generateMulticallSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const callRequests = [
      lib.generateCallRequest(
        '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
        lib.toWei('2.0'),
      ),
      lib.generateCallRequest(
        '0x4355e3DAc64C3Cd555E60BA829b27e4E44802B6b',
        lib.toWei('5.0'),
      ),
    ];
    const deadline = Math.floor(Date.now()/ 1000);
    const chainId = lib.CHAIN_IDS['HYCHAIN'];
    const callRequestSignature = await lib.generateMulticallSignature(wallet, callRequests, deadline, chainId);

    callRequestSignature.length.should.equal(132);
  });

  it('generateMulticallRequirements()', async () => {
    const wallet = lib.generateRandomWallet();
    const deadline = Math.floor(Date.now()/ 1000);
    const chainId = lib.CHAIN_IDS['HYCHAIN'];
    
    const multicallRequirements = await lib.generateMulticallRequirements(
      wallet,
      [ '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', '0x4355e3DAc64C3Cd555E60BA829b27e4E44802B6b' ],
      [],
      [],
      [],
      [ lib.toWei('2.0'), lib.toWei('5.0') ],
      [ '1', '2' ],
      deadline,
      chainId,
    );

    multicallRequirements.should.be.an('object');
    multicallRequirements.callRequests[0].should.be.an('array');
    multicallRequirements.signature.should.be.a('string');
    multicallRequirements.deadline.should.be.a('number');
    multicallRequirements.chainId.should.be.a('number');
  });

  it('generateScaCreationProofSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const scaCreationProofSignature = await lib.generateScaCreationProofSignature(wallet);

    scaCreationProofSignature.length.should.equal(132);
  });

  it('generateNonceSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const nonceSignature = await lib.generateNonceSignature(wallet);

    nonceSignature.should.have.property('nonce');
    nonceSignature.should.have.property('signature');
    nonceSignature.signature.length.should.equal(132);
  });

  it('generateUpgradeSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const upgradeSignature = await lib.generateUpgradeSignature(
      wallet,
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', // random addr for testing
      '0x',
      Math.floor(Date.now() / 1000),
      lib.CHAIN_IDS['HYCHAIN'],
    );

    upgradeSignature.length.should.equal(132);
  });

  it('generateSessionRequestTuple()', async () => {
    const sessionRequest = {
      nativeAllowance: '100',
      contractFunctionSelectors: [
        {
          address: '0xB40cdD7599d8f52C48f29E10CFBf24918C85F7cC',
          functionSelectors: [ '0x40c10f19', 'registerVoters(address[], uint256, uint256[2], tuple(uint256, string, address)[])' ],
        },
      ],
      erc20Allowances: [
        {
          address: '0xcccCb68e1A848CBDB5b60a974E07aAE143ed40C3',
          allowance: '100',
        },
      ],
      erc721Allowances: [
        {
          address: '0x8d9710f0e193d3f95c0723eaaf1a81030dc9116d',
          approveAll: true,
        },
      ],
      erc1155Allowances: [
        {
          address: '0x98e62fe371519d1d07e6f5bfce04737d4dacabfd',
          approveAll: true,
        },
      ],
    };

    const sessionRequestTuple = await lib.generateSessionRequestTuple(sessionRequest);

    sessionRequestTuple[0].should.equal(sessionRequest.nativeAllowance);
    sessionRequestTuple[1][0][0].should.equal(sessionRequest.contractFunctionSelectors[0].address);
    sessionRequestTuple[2][0][0].should.equal(sessionRequest.erc20Allowances[0].address);
    sessionRequestTuple[3][0][0].should.equal(sessionRequest.erc721Allowances[0].address);
    sessionRequestTuple[4][0][0].should.equal(sessionRequest.erc1155Allowances[0].address);
  });

  it('generateSessionSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const sessionSignature = await lib.generateSessionSignature(
      wallet,
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
      { nativeAllowance: '0' },
      Date.now(),
      1,
      Date.now(),
      1,
    );

    sessionSignature.should.be.a('string');
    sessionSignature.length.should.equal(132);
  });

  it('generateUser()', async () => {
    const username = 'iamarkdev';
    const email = 'ark@hychain.com';
    const passwordOrKeyMaterial = 'testing';
    const user = await lib.generateUser(username, passwordOrKeyMaterial, email);

    user.should.have.property('username');
    user.should.have.property('email');
    user.should.have.property('salt');
    user.should.have.property('authorityAddress');
    user.should.have.property('authorityCiphertext');
    user.should.have.property('authorityProofSignature');
    user.username.should.equal(username);
    user.email.should.equal(email);

    const decryptedWallet = await lib.aesDecryptWalletWithPasswordOrKeyMaterial(user.authorityCiphertext, passwordOrKeyMaterial, user.salt);

    decryptedWallet.should.be.an('object');
  });

  it('generateAuthority()', async () => {
    const passwordOrKeyMaterial = 'testing';
    const authority = await lib.generateAuthority(passwordOrKeyMaterial);

    authority.should.have.property('salt');
    authority.should.have.property('authorityAddress');
    authority.should.have.property('authorityCiphertext');
    authority.should.have.property('authorityProofSignature');

    const decryptedWallet = await lib.aesDecryptWalletWithPasswordOrKeyMaterial(authority.authorityCiphertext, passwordOrKeyMaterial, authority.salt);

    decryptedWallet.should.be.an('object');
  });

  it('generateBackupCode()', () => {
    const backupCode = lib.generateBackupCode();
    const backupCodeTwo = lib.generateBackupCode();

    backupCode.length.should.equal(10);
    backupCode.should.not.equal(backupCodeTwo);
  });

  it('generateBackupQuestions()', () => {
    const backupQuestions = lib.generateBackupQuestions();

    backupQuestions.length.should.equal(10);
  });

  it('getWallet()', () => {
    const wallet = lib.generateRandomWallet();
    const walletCredentials = lib.getWalletCredentials(wallet);
    const wallet2 = lib.getWallet(walletCredentials);

    wallet2.address.should.equal(wallet.address);
    wallet2.mnemonic.phrase.should.equal(wallet.mnemonic.phrase);
  });

  it('getWalletCredentials()', () => {
    const wallet = lib.generateRandomWallet();
    const walletCredentials = lib.getWalletCredentials(wallet);

    walletCredentials.should.have.property('address');
    walletCredentials.should.have.property('privateKey');
    walletCredentials.should.have.property('mnemonic');

    walletCredentials.address.length.should.equal(42);
    walletCredentials.privateKey.length.should.equal(66);
  });

  it('toWei()', () => {
    const wei = lib.toWei('1.0');

    wei.should.be.a('bigint');
  });

  it('toEther()', () => {
    const ether = lib.toEther(BigInt('1000000000000000000'));

    ether.should.equal('1.0');
  });

  it('toSha256()', async () => {
    const hash = await lib.toSha256('sometext');

    hash.should.equal('5fb2054478353fd8d514056d1745b3a9eef066deadda4b90967af7ca65ce6505');
  });
});
