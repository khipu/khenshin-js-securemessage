define("SecureMessage", ["require", "exports", "tweetnacl", "tweetnacl-util"], function (require, exports, tweetnacl_1, tweetnacl_util_1) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    class SecureMessage {
        constructor() {
            this.newNonceS = () => tweetnacl_1.randomBytes(tweetnacl_1.secretbox.nonceLength);
            this.newNonceA = () => tweetnacl_1.randomBytes(tweetnacl_1.box.nonceLength);
            this.SymmetricKeys = new Map();
            const newKey = tweetnacl_1.box.keyPair();
            this.publicKey = tweetnacl_util_1.encodeBase64(newKey.publicKey);
            this.privateKey = tweetnacl_util_1.encodeBase64(newKey.secretKey);
        }
        static getInstance() {
            if (SecureMessage._instance === null) {
                SecureMessage._instance = new SecureMessage();
            }
            return SecureMessage._instance;
        }
        encrypt(plainText, receiverPubKey, reuseExistingKey = true) {
            let symmetricKey;
            if (!this.SymmetricKeys.has(receiverPubKey) || !reuseExistingKey) {
                symmetricKey = this.encryptSymmetricKey(receiverPubKey);
                if (reuseExistingKey) {
                    this.SymmetricKeys.set(receiverPubKey, symmetricKey);
                }
            }
            else {
                symmetricKey = this.SymmetricKeys.get(receiverPubKey);
            }
            if (symmetricKey === undefined) {
                throw new Error('Can not obtain the symmetric key');
            }
            const nonce = this.newNonceS();
            const keyUint8Array = tweetnacl_util_1.decodeBase64(symmetricKey.raw);
            if (typeof plainText !== 'object') {
                throw new Error('Only JSON object accepted as an input');
            }
            const messageUint8 = tweetnacl_util_1.decodeUTF8(plainText);
            const newBox = tweetnacl_1.secretbox(messageUint8, nonce, keyUint8Array);
            const fullMessage = new Uint8Array(nonce.length + newBox.length);
            fullMessage.set(nonce);
            fullMessage.set(newBox, nonce.length);
            const fullMessageAsBase64 = tweetnacl_util_1.encodeBase64(fullMessage);
            return `${fullMessageAsBase64}.${symmetricKey.enc}`;
        }
        encryptSymmetricKey(publicKey) {
            const symmetricKey = tweetnacl_util_1.encodeBase64(tweetnacl_1.randomBytes(tweetnacl_1.secretbox.keyLength));
            const nonce = this.newNonceA();
            const finalKey = this.getShared(publicKey);
            const pubKeyAsUint8Array = tweetnacl_util_1.decodeBase64(finalKey);
            const messageUint8 = tweetnacl_util_1.decodeUTF8(JSON.stringify({ key: symmetricKey }));
            const encrypted = tweetnacl_1.box.after(messageUint8, nonce, pubKeyAsUint8Array);
            const fullMessage = new Uint8Array(nonce.length + encrypted.length);
            fullMessage.set(nonce);
            fullMessage.set(encrypted, nonce.length);
            return {
                raw: symmetricKey,
                enc: tweetnacl_util_1.encodeBase64(fullMessage),
            };
        }
        getShared(publicKey) {
            const publicKeyAsUint8Array = tweetnacl_util_1.decodeBase64(publicKey);
            const privateKeyAsUint8Array = tweetnacl_util_1.decodeBase64(this.privateKey);
            return tweetnacl_util_1.encodeBase64(tweetnacl_1.box.before(publicKeyAsUint8Array, privateKeyAsUint8Array));
        }
        decrypt(cipherText, senderPublicKey, reuseExistingKey = true) {
            const dataParts = cipherText.split('.');
            if (dataParts.length !== 2) {
                throw new Error('Payload is corrupted');
            }
            let symmetricKey;
            if (!this.SymmetricKeys.has(senderPublicKey) || !reuseExistingKey) {
                symmetricKey = this.decryptSymmetricKey(dataParts[1], senderPublicKey);
                if (reuseExistingKey) {
                    this.SymmetricKeys.set(senderPublicKey, symmetricKey);
                }
            }
            else {
                symmetricKey = this.SymmetricKeys.get(senderPublicKey);
            }
            const keyUint8Array = tweetnacl_util_1.decodeBase64(symmetricKey);
            const messageWithNonceAsUint8Array = tweetnacl_util_1.decodeBase64(dataParts[0]);
            const nonce = messageWithNonceAsUint8Array.slice(0, tweetnacl_1.secretbox.nonceLength);
            const message = messageWithNonceAsUint8Array.slice(tweetnacl_1.secretbox.nonceLength, dataParts[0].length);
            const decrypted = tweetnacl_1.secretbox.open(message, nonce, keyUint8Array);
            if (!decrypted) {
                throw new Error('Could not decrypt message');
            }
            return tweetnacl_util_1.encodeUTF8(decrypted);
        }
        decryptSymmetricKey(messageWithNonce, publicKey) {
            const finalKey = this.getShared(publicKey);
            const privateKeyAsUint8Array = tweetnacl_util_1.decodeBase64(finalKey);
            const messageWithNonceAsUint8Array = tweetnacl_util_1.decodeBase64(messageWithNonce);
            const nonce = messageWithNonceAsUint8Array.slice(0, tweetnacl_1.box.nonceLength);
            const message = messageWithNonceAsUint8Array.slice(tweetnacl_1.box.nonceLength, messageWithNonce.length);
            const decrypted = tweetnacl_1.box.open.after(message, nonce, privateKeyAsUint8Array);
            if (!decrypted) {
                throw new Error('Could not decrypt the key');
            }
            const jsonObject = JSON.parse(tweetnacl_util_1.encodeUTF8(decrypted));
            return jsonObject.key;
        }
    }
    exports.default = SecureMessage;
    SecureMessage._instance = null;
});
