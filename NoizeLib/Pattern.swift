//
// Created by Sergey Brazhnik on 12.04.2023.
//

import Foundation
import CryptoKit

struct Pattern {
    var name: String
    var preSharedMessagePatterns: [[Token]]
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

    public func hash(data: Data) -> Data{
        var alg = hashAlg
        alg.update(data: data)
        let res = alg.finalize()
        return Data(res)
    }

    static let Noise_XN_25519_ChaChaPoly_SHA256 =
            Pattern(name: "Noise_XN_25519_ChaChaPoly_SHA256",
                    preSharedMessagePatterns: [],
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
