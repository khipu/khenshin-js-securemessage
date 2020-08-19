declare module 'khenshin-js-securemessage' {
    export default class SecureMessage {
        publicKey: string

        static getInstance(): SecureMessage

        encrypt(plainText: string, receiverPubKey: string, reuseExistingKey?: boolean): string

        decrypt(cipherText: string, senderPublicKey: string, reuseExistingKey?: boolean): string
    }
}

