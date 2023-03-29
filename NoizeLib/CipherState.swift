//
// Created by Sergey Brazhnik on 27.03.2023.
//
import CryptoKit
import Foundation

protocol CipherState {
    init(k: Data?, nonce: UInt)

    // Returns true if k is non-empty, false otherwise.
    func hasKey() -> Bool

    // Sets n = nonce. This function is used for handling out-of-order transport messages, as described in Section 11.4.
    func setNonce(nonce: UInt)

    // If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
    func encryptWithAd(authenticationData: Data, plaintext: Data) throws -> Data

    // If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
    func decryptWithAd(authenticationData: Data, ciphertext: Data) throws -> Data

}

class CipherStateImpl: CipherState {

    var k: Data?
    var nonce: UInt
    required init(k: Data?, nonce: UInt = 0) {
        self.k = k
        self.nonce = nonce
    }

    func hasKey() -> Bool {
        k != nil
    }

    func setNonce(nonce: UInt) {
        self.nonce = nonce
    }

    func encryptWithAd(authenticationData: Data, plaintext: Data) throws -> Data {
        if let encryptionKey = k {
            let key = SymmetricKey(data: encryptionKey)

            // increment nonce
            nonce = nonce + 1
            let chachanonce = try ChaChaPoly.Nonce(data: Data.fromInt(integer: nonce))

            let result = try ChaChaPoly.seal(plaintext, using: key , nonce: chachanonce, authenticating: authenticationData)
            return result.ciphertext
        } else {
            return plaintext
        }
    }

    func decryptWithAd(authenticationData: Data, ciphertext: Data) throws -> Data {
        if let encryptionKey = k {
            let key = SymmetricKey(data: encryptionKey)

            let chachaNonce = try ChaChaPoly.Nonce(data: Data.fromInt(integer: nonce))

            let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ciphertext, tag: <#T##T##T#>)
            let result = try ChaChaPoly.open(sealedBox, using: key, authenticating: authenticationData)
            nonce = nonce + 1
            return result
        } else {
            return ciphertext
        }
    }
}

enum Errors: Error {
    case noKey
}






