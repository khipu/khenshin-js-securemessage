import SecureMessage from "../src/SecureMessage";
const randomstring = require("randomstring")

describe('SecureMessage', () => {
    it('Should create public key', async () => {
        expect(SecureMessage.getInstance().publicKey !== undefined)
    })
    it('Should use a pre asigned public key', async () => {
        const key = "1231231231231332112123132"
        expect(SecureMessage.getInstance(key, 'xxx').publicKey === key)
    })
    it('encrypt and decrypt cycle', async () => {
        const sender = new SecureMessage()
        const reciver = new SecureMessage()

        const toEncrypt = randomstring.generate()
        console.log(`toEncrypt: ${toEncrypt}`)
        const encrypted = sender.encrypt(toEncrypt, reciver.publicKey)
        console.log(`encrypted: ${encrypted}`)
        const decrypted = reciver.decrypt(encrypted, sender.publicKey)
        console.log(`decrypted: ${decrypted}`)

        expect(toEncrypt === decrypted)
    })
})
