🔐 Mnemonic Wallet Derivation Explorer

⚠️ Educational Use Only
This tool is designed for research and learning purposes about BIP-39, BIP-44, and HD wallet derivation standards used in cryptocurrency wallets.
Do not use it to attempt access to wallets or addresses that you do not own.

📘 Overview

This project demonstrates how to:

Generate mnemonic seed phrases (BIP-39),

Derive HD wallet addresses using BIP-44 / BIP-49 / BIP-84 / BIP-86,

Compute and display private/public key pairs for multiple coins,

Compare generated addresses against a local database (for research or recovery).

It can be used to explore how different hierarchical deterministic (HD) derivation paths are used across cryptocurrencies such as Bitcoin, Ethereum, Solana, Litecoin, Dogecoin, XRP, Dash, and more.

⚙️ Features

🔁 Multi-process generation and verification system

🔤 Supports mnemonic lengths of 12, 15, 18, and 24 words

🧩 Compatible with multiple BIP standards (44/49/84/86)

💾 Automatic checkpointing and progress saving

📈 Live status updates (seed and address counts)

🗂️ SQLite-based address checking (optional, for offline testing)

🧠 How It Works

Producer process
Generates all possible mnemonic combinations from a given list of “popular words”.
Only valid BIP-39 mnemonics are queued for processing.

Worker processes
For each valid seed phrase:

Derives addresses for supported coins using bip-utils
.

(Optionally) checks if these addresses exist in a local database (alladdresses.db).

Logs matching results to znalezione_POPULAR.txt.

Progress Monitor
A background thread periodically prints statistics such as total generated seeds and derived addresses.

🪙 Supported Coins
Coin	Standards Supported
Bitcoin	BIP44, BIP49, BIP84, BIP86
Litecoin	BIP44, BIP49, BIP84
Ethereum	BIP44
Dogecoin	BIP44
XRP	BIP44
Dash	BIP44
Bitcoin Cash	BIP44
Solana	BIP44 (custom via nacl.signing)
🧩 File Structure
File	Description
main.py	Main program logic
popular_words12.txt	List of common mnemonic words to test
alladdresses.db	SQLite database containing addresses (optional)
checkpoint.json	Progress tracking file
znalezione_POPULAR.txt	Output file for found matches
🧰 Dependencies
pip install bip-utils mnemonic pynacl base58

▶️ Usage
python3 main.py


If a database file (alladdresses.db) exists, it will be opened in read-only mode.
The program will print progress in the console and write discovered results to znalezione_POPULAR.txt.

⚠️ Disclaimer

This software is provided for educational and research purposes only — for example, to:

Study how HD wallets generate keys and addresses,

Learn BIP-39 / BIP-44 derivation paths,

Experiment with your own wallets (e.g., partial recovery from known words).

Do not use it to try to gain unauthorized access to wallets, funds, or private keys belonging to others.
The author takes no responsibility for any misuse of this software.

🧑‍💻 Author

Created as an educational crypto research utility to understand wallet derivation, address generation, and mnemonic validation.
BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
