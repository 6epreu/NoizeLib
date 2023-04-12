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
    var cs: CipherState {get}

    init(pattern: Pattern)
    func mixKey(inputKey: Data)
    func mixHash(data: Data)
}

class SymmetricStateImpl : SymmetricState {
    private(set) var ck: Data
    private(set) var h: Data
    private(set) var cs: CipherState
    private var pattern: Pattern

    required init(pattern: Pattern) {
        self.pattern = pattern

        if pattern.name.count <= pattern.HASHLEN {
            let toAddCount = pattern.HASHLEN - pattern.name.count
            let toAddData = Data(repeating: 0, count: toAddCount)
            h = pattern.name.data(using: .utf8)! + toAddData
        } else {
            h = pattern.hash(data: pattern.name.data(using: .utf8)!)
        }

        ck = h
        cs = CipherStateImpl(k: nil)
    }

    func mixKey(inputKey: Data) {

    }

    func mixHash(data: Data) {
        var tempH = h
        tempH.append(data)
        h = pattern.hash(data: tempH)
    }

    // https://noiseprotocol.org/noise.html#hash-functions
    // HMAC-HASH
    // http://www.ietf.org/rfc/rfc2104.txt
    // H(K XOR opad, H(K XOR ipad, text))
    private func hmacHash(key: Data, data: Data) -> Data {
        //let ipad = 0x36
        //let ipad = Data(hex: "0x36")
        let ipad = Data(repeating: 0x36, count: 1)
        let opad = Data(repeating: 0x5C, count: 1)

        // K XOR ipad
        var kXORipad = key
        kXORipad.xor(key: ipad)

        // K XOR opad
        var kXORopad = key
        kXORopad.xor(key: opad)

        // H(K XOR ipad, text)
        let firstHash = pattern.hash(data: kXORipad + data)

        // H(K XOR opad, H(K XOR ipad, text))
        let result = pattern.hash(data: kXORopad + firstHash)
        return result
    }

    private func hkdf(chainingKey: Data, inputKeyMaterial: Data, numOutputs: Data) {

    }
}