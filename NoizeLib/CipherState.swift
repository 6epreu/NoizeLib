//
// Created by Sergey Brazhnik on 27.03.2023.
//
import CryptoKit
import Foundation

protocol CipherState {
    init(k: Data?, nonce: UInt64)

    // Returns true if k is non-empty, false otherwise.
    func hasKey() -> Bool

    // Sets n = nonce. This function is used for handling out-of-order transport messages, as described in Section 11.4.
    func setNonce(nonce: UInt64)

    // If k is non-empty returns ENCRYPT(k, n++, ad, plaintext). Otherwise returns plaintext.
    func encryptWithAd(authenticationData: Data, plaintext: Data) throws -> Data

    // If k is non-empty returns DECRYPT(k, n++, ad, ciphertext). Otherwise returns ciphertext. If an authentication failure occurs in DECRYPT() then n is not incremented and an error is signaled to the caller.
    func decryptWithAd(authenticationData: Data, ciphertext: Data) throws -> Data
}

class CipherStateImpl: CipherState {

    var k: Data?
    var nonce: UInt64
    required init(k: Data?, nonce: UInt64 = 0) {
        self.k = k
        self.nonce = nonce
    }

    func hasKey() -> Bool {
        k != nil
    }

    func setNonce(nonce: UInt64) {
        self.nonce = nonce
    }

    private func convertNonceToChaChaNonce() throws -> ChaChaPoly.Nonce {
        var nonceTemp = Data()
        nonceTemp.append(Data(repeating: 0, count: 4))
        nonceTemp.append(Data.fromInt(integer: nonce))
        return try ChaChaPoly.Nonce(data: nonceTemp)
    }

    private func incrementNonce() throws {
        nonce = nonce + 1
        if nonce >= UInt64.max {
            throw Errors.nonceOverflow
        }
    }


    /*
        Encryption of chacha
     - Parameters:
       - authenticationData:
       - plaintext:
     - Returns: cipherText || tag
     - Throws:*/
    func encryptWithAd(authenticationData: Data, plaintext: Data) throws -> Data {
        if let encryptionKey = k {
            let key = SymmetricKey(data: encryptionKey)

            let chachaNonce = try convertNonceToChaChaNonce()
            let result = try ChaChaPoly.seal(plaintext, using: key , nonce: chachaNonce, authenticating: authenticationData)

            try incrementNonce()

            var cipherText = Data()
            cipherText.append(result.ciphertext) // variant length
            cipherText.append(result.tag)   // 16 bytes
            return cipherText
        } else {
            return plaintext
        }
    }

    /*
        Decrypt
     - Parameters:
       - authenticationData:
       - ciphertext: cipherText || tag
     - Returns:
     - Throws:*/
    func decryptWithAd(authenticationData: Data, ciphertext: Data) throws -> Data {
        if let encryptionKey = k {
            let key = SymmetricKey(data: encryptionKey)

            let chachaNonce = try convertNonceToChaChaNonce()
            let encryptedText = ciphertext.subdata(in: 0..<ciphertext.count-16)
            let tag = ciphertext.subdata(in: ciphertext.count-16..<ciphertext.count)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: encryptedText, tag: tag)

            let result = try ChaChaPoly.open(sealedBox, using: key, authenticating: authenticationData)

            // increment nonce
            try incrementNonce()

            return result
        } else {
            return ciphertext
        }
    }
}

enum Errors: Error {
    case nonceOverflow
}






