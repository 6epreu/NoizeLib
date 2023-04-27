//
//  NoizeLibTests.swift
//  NoizeLibTests
//
//  Created by Sergey Brazhnik on 29.03.2023.
//

import CryptoKit
import Foundation
import XCTest
@testable import NoizeLib

class SymmetryTest: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }


    func testSymmetryNameEqual32() throws {
        let symmetry = SymmetricStateImpl(pattern: Pattern.Noise_XN_25519_ChaChaPoly_SHA256)
        XCTAssertEqual(symmetry.h, Pattern.Noise_XN_25519_ChaChaPoly_SHA256.name.data(using: .utf8)!)
    }

    func testSymmetryNameMoreThen32() throws {
        let pattern = Pattern(name: "Noise_XXfallback_25519_ChaChaPoly_SHA256",
                preSharedMessagePatternsInitiator: [],
                preSharedMessagePatternsResponder: [],
                messagePatterns: [])

        let symmetry = SymmetricStateImpl(pattern: pattern)

        var sha = SHA256()
        sha.update(data: pattern.name.data(using: .utf8)!)
        let hash = Data(sha.finalize())
        XCTAssertEqual(symmetry.h, hash)
    }

    func testSymmetryNameLessThen32() throws {
        let pattern =
                Pattern(name: "Noise_x_x_x_SHA256",
                        preSharedMessagePatternsInitiator: [],
                        preSharedMessagePatternsResponder: [],
                        messagePatterns: [])

        let symmetry = SymmetricStateImpl(pattern: pattern)

        let name = pattern.name.data(using: .utf8)! + Data(repeating: 0x00, count: 14)
        XCTAssertEqual(symmetry.h, name)
    }

    func testHKDF() throws {
        let symmetry = SymmetricStateImpl(pattern: Pattern.Noise_XN_25519_ChaChaPoly_SHA256)
        let inputKeyMaterial = Data(repeating: 0x77, count: 32)
        let ck = Data(repeating: 0x01, count: 32)

        let res = try symmetry.hkdf(chainingKey: ck, inputKeyMaterial: inputKeyMaterial, numOutputs: 3)
        print("res.0 = \(res.0.hex) res.1 = \(res.1.hex) res.2 = \(res.2.hex)")


        let cryptoKitRes = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: inputKeyMaterial), salt: ck, info: Data(), outputByteCount: 32)
        let cryptoKitResData = cryptoKitRes.withUnsafeBytes {
            return Data(Array($0))
        }
        print("cryptoKitRes = \(cryptoKitResData.hex) ")

        XCTAssertEqual(res.0.hex, cryptoKitResData.hex)
    }

    func testMixKey() throws {
        let pattern = Pattern.Noise_XN_25519_ChaChaPoly_SHA256
        let symmetry = SymmetricStateImpl(pattern: pattern)

        let ckBefore = symmetry.ck
        let inputKeyMaterial = Data(repeating: 0x77, count: 32)
        symmetry.mixKey(inputKeyMaterial: inputKeyMaterial)

        let cryptoKitRes = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: inputKeyMaterial), salt: ckBefore, info: Data(), outputByteCount: 32)
        let cryptoKitResData = cryptoKitRes.withUnsafeBytes {
            return Data(Array($0))
        }
        XCTAssertEqual(symmetry.ck.hex, cryptoKitResData.hex)
    }

    func testMixHash() {
        let pattern = Pattern.Noise_XN_25519_ChaChaPoly_SHA256
        let symmetry = SymmetricStateImpl(pattern: pattern)
        let toMix = Data(repeating: 0x01, count: 32)
        symmetry.mixHash(data: Data(repeating: 0x01, count: 32))

        let h = Pattern.Noise_XN_25519_ChaChaPoly_SHA256.name.data(using: .utf8)! + toMix

        var alg = SHA256()
        alg.update(data: h)
        let res = Data(alg.finalize())

        XCTAssertEqual(res, symmetry.getHandshakeHash())
    }

    func testEncryptDecrypt() {
        let symmetry1 = SymmetricStateImpl(pattern: Pattern.Noise_XN_25519_ChaChaPoly_SHA256)
        let plainText = "Hello worlds".data(using: .utf8)!
        let cipherText = symmetry1.encryptAndHash(plainText: plainText)

        let symmetry2 = SymmetricStateImpl(pattern: Pattern.Noise_XN_25519_ChaChaPoly_SHA256)
        let decryptedText = symmetry2.decryptAndHash(cipherText: cipherText)

        XCTAssertEqual(plainText, decryptedText)
    }
}
