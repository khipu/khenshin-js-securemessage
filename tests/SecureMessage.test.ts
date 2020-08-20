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
        const server = new SecureMessage()
        const client = new SecureMessage()
        const toEncrypt = randomstring.generate()
        const encrypted = server.encrypt(toEncrypt, client.publicKey)
        const decrypted = client.decrypt(encrypted, server.publicKey)
        expect(toEncrypt === decrypted)

        const toEncrypt2 = randomstring.generate()
        const encrypted2 = client.encrypt(toEncrypt2, server.publicKey)
        const decrypted2 = server.decrypt(encrypted2, client.publicKey)
        expect(toEncrypt2 === decrypted2)

    })
})
