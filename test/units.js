const lib = require('../');

const chai = require('chai');
chai.should();

describe('Unit Tests', () => {
  it('aesEncrypt(), aesDecrypt(), pbkdf2()', async () => {
    const plaintext = 'sometext';
    const password = 'password';
    const pbkdf2Key = await lib.pbkdf2(password, 'someSalt');
    const ciphertext = await lib.aesEncrypt(plaintext, pbkdf2Key);
    const decrypted = await lib.aesDecrypt(ciphertext, pbkdf2Key);

    decrypted.should.equal(plaintext);
  });

  it('aesEncryptWalletWithPassword(), aesDecryptWalletWithPassword()', async () => {
    const wallet = lib.generateRandomWallet();
    const password = 'somepass';
    const salt = lib.generateRandomSalt();
    const ciphertext = await lib.aesEncryptWalletWithPassword(wallet, password, salt);
    const decryptedWallet = await lib.aesDecryptWalletWithPassword(ciphertext, password, salt);

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

  it('generateCallRequestsSignature()', async () => {
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
    const callRequestSignature = await lib.generateCallRequestsSignature(wallet, callRequests, deadline, chainId);

    callRequestSignature.length.should.equal(132);
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

  it('generateSessionSignature()', async () => {
    const wallet = lib.generateRandomWallet();
    const sessionSignature = await lib.generateSessionSignature(
      wallet,
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
      [ 0, [], [], [], [] ],
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
    const password = 'testing';
    const user = await lib.generateUser(username, password, email);

    user.should.have.property('username');
    user.should.have.property('email');
    user.should.have.property('salt');
    user.should.have.property('authorityAddress');
    user.should.have.property('authorityCiphertext');
    user.should.have.property('authorityProofSignature');
    user.username.should.equal(username);
    user.email.should.equal(email);

    const decryptedWallet = await lib.aesDecryptWalletWithPassword(user.authorityCiphertext, password, user.salt);

    decryptedWallet.should.be.an('object');
  });

  it('generateAuthority()', async () => {
    const password = 'testing';
    const authority = await lib.generateAuthority(password);

    authority.should.have.property('salt');
    authority.should.have.property('authorityAddress');
    authority.should.have.property('authorityCiphertext');
    authority.should.have.property('authorityProofSignature');

    const decryptedWallet = await lib.aesDecryptWalletWithPassword(authority.authorityCiphertext, password, authority.salt);

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
