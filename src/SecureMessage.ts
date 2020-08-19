import {box, randomBytes, secretbox} from 'tweetnacl'
import {decodeBase64, decodeUTF8, encodeBase64, encodeUTF8} from 'tweetnacl-util'

interface Key {
    raw: string
    enc: string
}

export default class SecureMessage {
    private static _instance: SecureMessage | null = null

    private newNonceS = () => randomBytes(secretbox.nonceLength)
    private newNonceA = () => randomBytes(box.nonceLength)

    readonly publicKey: string
    private readonly privateKey: string
    private SymmetricKeys: Map<string, Key> = new Map<string, Key>()

    constructor(publicKeyBase64?: string, privateKeyBase64?: string) {
        if (publicKeyBase64 !== undefined && privateKeyBase64 !== undefined) {
            this.publicKey = publicKeyBase64
            this.privateKey = privateKeyBase64
        } else {
            const newKey = box.keyPair()
            this.publicKey = encodeBase64(newKey.publicKey)
            this.privateKey = encodeBase64(newKey.secretKey)
        }
    }

    static configure(publicKeyBase64?: string, privateKeyBase64?: string): void {
        SecureMessage._instance = new SecureMessage(publicKeyBase64, privateKeyBase64)
    }

    static getInstance(): SecureMessage {
        if (SecureMessage._instance === null) {
            throw new Error("Instance not configured, call configure first")
        }
        return SecureMessage._instance
    }

    public encrypt(plainText: string, receiverPubKey: string, reuseExistingKey: boolean = true): string {
        let symmetricKey

        if (!this.SymmetricKeys.has(receiverPubKey) || !reuseExistingKey) {
            symmetricKey = this.encryptSymmetricKey(receiverPubKey)
            if (reuseExistingKey) {
                this.SymmetricKeys.set(receiverPubKey, symmetricKey)
            }
        } else {
            symmetricKey = this.SymmetricKeys.get(receiverPubKey)
        }
        if (symmetricKey === undefined) {
            throw new Error('Can not obtain the symmetric key')
        }
        const nonce = this.newNonceS()
        const keyUint8Array = decodeBase64(symmetricKey.raw)

        const messageUint8 = decodeUTF8(plainText)
        const newBox = secretbox(messageUint8, nonce, keyUint8Array)

        const fullMessage = new Uint8Array(nonce.length + newBox.length)
        fullMessage.set(nonce)
        fullMessage.set(newBox, nonce.length)

        const fullMessageAsBase64 = encodeBase64(fullMessage)

        return `${fullMessageAsBase64}.${symmetricKey.enc}`
    }

    private encryptSymmetricKey(publicKey: string): Key {
        const symmetricKey = encodeBase64(randomBytes(secretbox.keyLength))

        const nonce = this.newNonceA()
        const finalKey = this.getShared(publicKey)
        const pubKeyAsUint8Array = decodeBase64(finalKey)

        const messageUint8 = decodeUTF8(JSON.stringify({key: symmetricKey}))

        const encrypted = box.after(messageUint8, nonce, pubKeyAsUint8Array)

        const fullMessage = new Uint8Array(nonce.length + encrypted.length)
        fullMessage.set(nonce)
        fullMessage.set(encrypted, nonce.length)

        return {
            raw: symmetricKey,
            enc: encodeBase64(fullMessage),
        }
    }

    private getShared(publicKey: string) {
        const publicKeyAsUint8Array = decodeBase64(publicKey)
        const privateKeyAsUint8Array = decodeBase64(this.privateKey)

        return encodeBase64(box.before(publicKeyAsUint8Array, privateKeyAsUint8Array))
    }

    public decrypt(cipherText: string, senderPublicKey: string, reuseExistingKey: boolean = true): string {
        const dataParts = cipherText.split('.')
        if (dataParts.length !== 2) {
            throw new Error('Payload is corrupted')
        }

        let symmetricKey

        if (!this.SymmetricKeys.has(senderPublicKey) || !reuseExistingKey) {
            symmetricKey = this.decryptSymmetricKey(dataParts[1], senderPublicKey)
            if (reuseExistingKey) {
                this.SymmetricKeys.set(senderPublicKey, symmetricKey)
            }
        } else {
            symmetricKey = this.SymmetricKeys.get(senderPublicKey)
        }

        const keyUint8Array = decodeBase64(symmetricKey)
        const messageWithNonceAsUint8Array = decodeBase64(dataParts[0])

        const nonce = messageWithNonceAsUint8Array.slice(0, secretbox.nonceLength)
        const message = messageWithNonceAsUint8Array.slice(secretbox.nonceLength, dataParts[0].length)

        const decrypted = secretbox.open(message, nonce, keyUint8Array)

        if (!decrypted) {
            throw new Error('Could not decrypt message')
        }

        return encodeUTF8(decrypted)
    }

    private decryptSymmetricKey(messageWithNonce: string, publicKey: string) {
        const finalKey = this.getShared(publicKey)
        const privateKeyAsUint8Array = decodeBase64(finalKey)
        const messageWithNonceAsUint8Array = decodeBase64(messageWithNonce)
        const nonce = messageWithNonceAsUint8Array.slice(0, box.nonceLength)
        const message = messageWithNonceAsUint8Array.slice(box.nonceLength, messageWithNonce.length)

        const decrypted = box.open.after(message, nonce, privateKeyAsUint8Array)

        if (!decrypted) {
            throw new Error('Could not decrypt the key')
        }
        const jsonObject = JSON.parse(encodeUTF8(decrypted))
        return jsonObject.key
    }
}
