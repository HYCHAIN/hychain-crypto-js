const lib = require('../');

const chai = require('chai');
chai.should();

describe('Unit Tests', () => {
  it('aesEncryptWallet()', () => {
    const wallet = lib.generateRandomWallet();
    const password = 'mycoolpass';
    const salt = lib.generateRandomSalt();
    const ciphertext = lib.aesEncryptWallet(wallet, password, salt);

    ciphertext.length.should.be.gte(300);
  });

  it('aesDecryptWallet()', () => {
    const wallet = lib.generateRandomWallet();
    const password = 'somepass';
    const salt = lib.generateRandomSalt();
    const ciphertext = lib.aesEncryptWallet(wallet, password, salt);
    const decryptedWallet = lib.aesDecryptWallet(ciphertext, password, salt);

    decryptedWallet.address.should.equal(wallet.address);
    decryptedWallet.mnemonic.phrase.should.equal(wallet.mnemonic.phrase);
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

  it('generateCallRequestData()', () => {
    const callRequestData = lib.generateCallRequestData(
      'transfer(address,uint256)',
      [ 'address', 'uint256' ],
      [ '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3', 100 ],
    );

    callRequestData.should.equal('0xa9059cbb000000000000000000000000ccccb68e1a848cbdb5b60a974e07aae143ed40c30000000000000000000000000000000000000000000000000000000000000064');
  });

  it('generateCallRequest()', () => {
    const callRequest = lib.generateCallRequest(
      '0xccccb68e1a848cbdb5b60a974e07aae143ed40c3',
      lib.toWei('2.0'),
      '',
    );

    callRequest.should.be.an('object');
    callRequest.nonce.should.be.a('string');
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
      '',
    );
    const chainId = lib.CHAIN_IDS['HYTOPIA'];
    const callRequestSignature = await lib.generateCallRequestSignature(wallet, callRequest, chainId);

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

  it('generateUser()', async () => {
    const username = 'iamarkdev';
    const email = 'ark@hytopia.com';
    const phone = undefined;
    const password = 'testing';
    const user = await lib.generateUser(username, email, phone, password);

    user.should.have.property('username');
    user.should.have.property('email');
    user.should.have.property('phone');
    user.should.have.property('salt');
    user.should.have.property('authorityAddress');
    user.should.have.property('authorityCiphertext');
    user.should.have.property('authorityProofSignature');
    user.username.should.equal(username);
    user.email.should.equal(email);

    const decryptedWallet = lib.aesDecryptWallet(user.authorityCiphertext, password, user.salt);

    decryptedWallet.should.be.an('object');
  });

  it('getWalletCredentials()', () => {
    const wallet = lib.generateRandomWallet();
    const walletCredentials = lib.getWalletCredentials(wallet);

    walletCredentials.should.have.property('address');
    walletCredentials.should.have.property('privateKey');
    walletCredentials.should.have.property('mnemonic');

    walletCredentials.address.length.should.equal(42)
    walletCredentials.privateKey.length.should.equal(66);
  });

  it('toWei', () => {
    const wei = lib.toWei('1.0');

    wei.should.be.a('bigint');
  });

  it('toEther', () => {
    const ether = lib.toEther(BigInt('1000000000000000000'));

    ether.should.equal('1.0');
  });
});
