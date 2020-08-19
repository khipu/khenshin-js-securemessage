import SecureMessage from "../src/SecureMessage";
const randomstring = require("randomstring")

describe('SecureMessage', () => {
    it('Must configure first', async () => {
        try{
            SecureMessage.getInstance()
        } catch (e) {
            expect(e.message === "Instance not configured, call configure first")
        }

    })
    it('Should create public key', async () => {
        SecureMessage.configure()
        expect(SecureMessage.getInstance().publicKey !== undefined)
    })
    it('Should use a pre asigned public key', async () => {
        const key = "1231231231231332112123132"
        SecureMessage.configure(key, 'xxx')
        expect(SecureMessage.getInstance().publicKey === key)
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
