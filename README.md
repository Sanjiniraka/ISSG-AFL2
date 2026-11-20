# Secure Chat App

Node.js + Socket.IO chat secured with SHA-256 hashing, RSA signatures, and RSA encryption.

## Setup
npm install

## Run
node server.js            # honest server
node malicious-server.js  # tampering server (demo)
node client.js            # normal client
node malicious-client.js  # impersonating client (demo)

## Features
1. SHA-256 hash detects message tampering by the server
2. RSA signature detects user impersonation
3. RSA encryption for secret messages (!secret <username>, !exit)