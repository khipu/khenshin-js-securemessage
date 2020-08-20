declare module 'khenshin-js-securemessage' {
    export default class SecureMessage {
        publicKey: string

        static configure(publicKeyBase64?: string, privateKeyBase64?: string): void

        static getInstance(): SecureMessage

        encrypt(plainText: string, receiverPubKey: string): string

        decrypt(cipherText: string, senderPublicKey: string): string
    }
}

