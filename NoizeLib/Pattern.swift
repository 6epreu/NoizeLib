//
// Created by Sergey Brazhnik on 12.04.2023.
//

import Foundation
import CryptoKit

struct Pattern {
    var name: String
    // A pre-message pattern for the initiator, representing information about the initiator's public keys that is known to the responder.
    var preSharedMessagePatternsInitiator: [Token]
    // A pre-message pattern for the responder, representing information about the responder's public keys that is known to the initiator.
    var preSharedMessagePatternsResponder: [Token]
    // A sequence of message patterns for the actual handshake messages.
    var messagePatterns: [[Token]]

    // example Noise_XX_25519_AESGCM_SHA256
    // [0] = Noise
    // [1] = XX - name the handshake pattern
    // [2] = 25519 - the DH functions
    // [3] = AESGCM - the cipher functions
    // [4] = SHA256 - the hash functions
    var HASHLEN: Int {
        let res = name.split(separator: "_")

        switch res[4] {
        case "SHA256": return 32
        default: return 32
        }
    }

    var BLOCKLEN: Int {
        let res = name.split(separator: "_")

        switch res[4] {
        case "SHA256": return 64
        default: return 64
        }
    }

    var hashAlg: any HashFunction {
        let res = name.split(separator: "_")

        switch res[4] {
        case "SHA256": return SHA256()
        default: return SHA256()
        }
    }

    // for now only supported algorithm
    var keyGenAlgKey: Curve25519.KeyAgreement.PrivateKey {
        let res = name.split(separator: "_")

        switch res[2] {
        case "25519": return Curve25519.KeyAgreement.PrivateKey()
        default: return Curve25519.KeyAgreement.PrivateKey()
        }
    }

    // for now only supported algorithm
    var dhAlg: (Data, Data) throws -> Data {
        let res = name.split(separator: "_")
        switch res[2] {
        case "25519":
            return agreement25519
        default:
            return agreement25519
        }
    }

    var DHLEN: Int {
        let res = name.split(separator: "_")
        switch res[2] {
        case "25519": return 32
        case "448": return 56
        default: return 32
        }
    }

    func agreement25519(privateKey: Data, publicKey: Data) throws -> Data {
        let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        let shared = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
        let sharedData = shared.withUnsafeBytes {
            return Data(Array($0))
        }
        return sharedData
    }

    public func hash(data: Data) -> Data {
        var alg = hashAlg
        alg.update(data: data)
        let res = alg.finalize()
        return Data(res)
    }

    static let Noise_XN_25519_ChaChaPoly_SHA256 =
            Pattern(name: "Noise_XN_25519_ChaChaPoly_SHA256",
                    preSharedMessagePatternsInitiator: [],
                    preSharedMessagePatternsResponder: [],
                    messagePatterns: [[.E], [.E, .EE], [.S, .SE]])

}

enum Token {
    case E
    case S
    case EE
    case ES
    case SE
    case SS
}

extension Curve25519.KeyAgreement.PrivateKey {
    var pair: (public: Data, private: Data) {
        (self.publicKey.rawRepresentation, self.rawRepresentation)
    }
}
