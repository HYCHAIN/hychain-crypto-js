# HYTOPIA Crypto JS
A helper package for the HYTOPIA web, client & api. Used to simplify management of various required cryptographic operations specific to user accounts.

HYTOPIA's account architecture retains the private key on the player's client device, and only transmits an AES encrypted version of their keys to HYTOPIA servers for the sake of being able to sign into other devices.

## Client Implementation Overview
Brief implementation summaries of patterns for client implementation.

### Account Creation
1. Client generates random wallet, random salt.
1. Client uses provided account password and salt to aes encrypt wallet.
1. Client sends account creation credentials to HYTOPIA servers: email/phone/socialAuthToken, wallet ciphertext, plaintext salt.

### Account Login
1. Client logs in using method tied to account: email, phone or socialAuthToken. Initiates 2fa challenge for email/phone, skip to 3 for social auth
1. If email or phone used, verification code sent to email or phone, entered on client
1. Account credentials returned to client, including wallet ciphertext and salt.
1. Client prompts player for their password to locally decrypt ciphertext first time they attempt to submit a CallRequest transaction or perform any wallet operation. Wallet credentials cached/encrypted locally - arbitrary local cache encryption key can be used.

## Test
You can run unit tests with `npm install && npm test`.
