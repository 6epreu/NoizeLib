//
// Created by Sergey Brazhnik on 12.04.2023.
//

import Foundation

/**
 A SymmetricState object contains a CipherState plus ck and h variables.
 It is so-named because it encapsulates all the "symmetric crypto" used by Noise.
 During the handshake phase each party has a single SymmetricState,
 which can be deleted once the handshake is finished.
 */
protocol SymmetricState {
    var ck: Data {get}
    var h: Data {get}
    var cipher: CipherState {get}

    init(pattern: Pattern)
    func mixKey(inputKeyMaterial: Data)
    func mixHash(data: Data)
    func mixKeyAndHash(inputKeyMaterial: Data)
    func getHandshakeHash() -> Data
    func encryptAndHash(plainText: Data) -> Data
    func decryptAndHash(cipherText: Data) -> Data
    func split() -> (CipherState, CipherState)
}

enum SymmetricStateErrors: Error {
    case invalidLength(String)
    case invalidArgument(String)
}

class SymmetricStateImpl : SymmetricState {
    private(set) var ck: Data
    private(set) var h: Data
    public var cipher: CipherState
    private var pattern: Pattern

    required init(pattern: Pattern) {
        self.pattern = pattern

        if pattern.name.count <= pattern.HASHLEN {
            h = Data(repeating: 0x00, count: pattern.HASHLEN)
            h.replaceSubrange(0..<pattern.name.count, with: pattern.name.data(using: .utf8)!)
        } else {
            h = pattern.hash(data: pattern.name.data(using: .utf8)!)
        }

        ck = h
        cipher = CipherStateImpl(k: nil)
    }

    func mixKey(inputKeyMaterial: Data) {
        let result = try! hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 2)
        ck = result.0
        var tempKey = result.1

        if pattern.HASHLEN == 64 {
            tempKey = tempKey.subdata(in: 0..<32)
        }

        cipher = CipherStateImpl(k: tempKey)
    }

    /**
     Sets h = HASH(h || data).
     - Parameter data: input data to hash
     */
    func mixHash(data: Data) {
        h = pattern.hash(data: h + data)
    }

    func mixKeyAndHash(inputKeyMaterial: Data) {
        let result = try! hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        ck = result.0

        var tempH = result.1
        mixHash(data: tempH)

        var tempKey = result.2
        if pattern.HASHLEN == 64 {
            tempKey = tempKey.subdata(in: 0..<32)
        }

        cipher = CipherStateImpl(k: tempKey)
    }

    func getHandshakeHash() -> Data {
        h
    }

    /**
    ciphertext = EncryptWithAd(h, plaintext), calls MixHash(ciphertext), and returns ciphertext.
    Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext.
     - Parameter plainText:
     - Returns: cipherText
     */
    func encryptAndHash(plainText: Data) -> Data {
        // todo for now counting no errors here. Future -> remove try!
        let cipherText = try! cipher.encryptWithAd(authenticationData: h, plaintext: plainText)
        mixHash(data: cipherText)
        return cipherText
    }

    /**
    Sets plaintext = DecryptWithAd(h, ciphertext), calls MixHash(ciphertext), and returns plaintext. Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext.
     - Parameter plaintext:
     - Returns:
     */
    func decryptAndHash(cipherText: Data) -> Data {
        // todo for now counting no errors here. Future -> remove try!
        let plainText = try! cipher.decryptWithAd(authenticationData: h, ciphertext: cipherText)
        mixHash(data: cipherText)
        return plainText
    }

    func split() -> (CipherState, CipherState) {
        // temp_k1, temp_k2 = HKDF(ck, zerolen, 2)
        let hkdfResult = try! hkdf(chainingKey: ck, inputKeyMaterial: Data(), numOutputs: 2)
        var tempKey1 = hkdfResult.0
        var tempKey2 = hkdfResult.1

        // If HASHLEN is 64, then truncates temp_k1 and temp_k2 to 32 bytes.
        if pattern.HASHLEN == 64 {
            tempKey1 = tempKey1.subdata(in: 0..<32)
            tempKey2 = tempKey2.subdata(in: 0..<32)
        }
        return (CipherStateImpl(k: tempKey1), CipherStateImpl(k: tempKey2))
    }




    /**
     https://noiseprotocol.org/noise.html#hash-functions
     HMAC-HASH
     http://www.ietf.org/rfc/rfc2104.txt
     H(K XOR opad, H(K XOR ipad, text))
     - Parameters:
       - key: key used for hmac operation
       - data: plain text
     - Returns: MAC = message authentication code deterministic output
     */
    private func hmacHash(key: Data, data: Data) -> Data {
        //let ipad = 0x36
        //let ipad = Data(hex: "0x36")
        let ipad = Data(repeating: 0x36, count: 1)
        let opad = Data(repeating: 0x5C, count: 1)

        var tempKey = key
        if key.count > pattern.BLOCKLEN {
            tempKey = pattern.hash(data: key)
        } else {
            tempKey = Data(repeating: 0x00, count: pattern.BLOCKLEN)
            tempKey.replaceSubrange(0..<key.count, with: key)
        }

        // K XOR ipad
        var kXORipad = tempKey
        kXORipad.xor(key: ipad)

        // K XOR opad
        var kXORopad = tempKey
        kXORopad.xor(key: opad)

        // H(K XOR ipad, text)
        let firstHash = pattern.hash(data: kXORipad + data)

        // H(K XOR opad, H(K XOR ipad, text))
        let result = pattern.hash(data: kXORopad + firstHash)
        return result
    }

    /**
        https://www.ietf.org/rfc/rfc5869.txt
     - Parameters:
       - chainingKey:
       - inputKeyMaterial:
       - numOutputs: number of rounds
     - Throws:
     - Returns:
     */
    public func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: Int) throws -> (Data, Data, Data){
        if chainingKey.count != pattern.HASHLEN {
            throw SymmetricStateErrors.invalidLength("Chaining key of length: \(chainingKey.count) have to be length of HASHLEN: \(pattern.HASHLEN)")
        }

        guard inputKeyMaterial.count == 0 || inputKeyMaterial.count == 32 /* todo || inputKeyMaterial.count == DHLEN */ else {
            throw SymmetricStateErrors.invalidLength("Input key material of length: \(inputKeyMaterial.count) have to be length of 0/32/DHLEN")
        }

        let tempKey = hmacHash(key: chainingKey, data: inputKeyMaterial)
        let output1 = hmacHash(key: tempKey, data: Data(repeating: 0x01, count: 1))
        let output2 = hmacHash(key: tempKey, data: output1 + Data(repeating: 0x02, count: 1))
        let output3 = hmacHash(key: tempKey, data: output2 + Data(repeating: 0x03, count: 1))

        if numOutputs == 2 {
            return (output1, output2, Data())
        } else if numOutputs == 3 {
            return (output1, output2, output3)
        } else {
            throw SymmetricStateErrors.invalidArgument("numOutputs should be 2 or 3. Now it's \(numOutputs)")
        }
    }


}