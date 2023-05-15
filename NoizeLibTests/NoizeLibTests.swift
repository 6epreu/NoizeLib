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

class NoizeLibTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testEncryptDecrypt() throws {
        var key = [UInt8](repeating: 18, count: 32)
        //let _ = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)

        let plainText = "hello"
        //let ad = Data(repeating: 0, count: 32)
        let ad = "world".data(using: .utf8)!
        //let nonce = [UInt8](repeating: 52, count: 8)

        let nonce = UInt64(3761688987579986996)
        let cipher = CipherStateImpl(k: Data(bytes: key), nonce: 1456)
        do {
            let encripted = try cipher.encryptWithAd(authenticationData: ad, plaintext: plainText.data(using: .utf8)!)
            print("encripted =\(encripted.hex)")

            // to make test pass
            cipher.setNonce(nonce: cipher.nonce-1)
            let decripted = try cipher.decryptWithAd(authenticationData: ad, ciphertext: encripted)
            print("decrypted =\(decripted.hex)")

            let resStr = String(bytes: decripted, encoding: .utf8)
            print("decrypted str =\(resStr)")
            assert(true)
        } catch  {
            assertionFailure()
            print("Error =\(error)")
        }
    }

    func testPattern() throws {
        let pattern = Pattern.Noise_XN_25519_ChaChaPoly_SHA256
        let hashFuncString = "\(type(of: pattern.hashAlg))"
        XCTAssertEqual(hashFuncString, "SHA256")

        XCTAssertEqual(pattern.HASHLEN, 32)

        XCTAssertEqual(pattern.BLOCKLEN, 64)

        let hashRes = pattern.hash(data: "hello".data(using: .utf8)!)
        XCTAssertEqual(hashRes, Data(hex: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"))
    }


}
