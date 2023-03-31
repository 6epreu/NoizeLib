//
//  NoizeLibTests.swift
//  NoizeLibTests
//
//  Created by Sergey Brazhnik on 29.03.2023.
//

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
        var key = [UInt8](repeating: 0, count: 32)
        let _ = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)

        let plainText = "Hello World!"
        let ad = Data(repeating: 0, count: 32)
        let cipher = CipherStateImpl(k: Data(bytes: key))
        do {
            let encripted = try cipher.encryptWithAd(authenticationData: ad, plaintext: plainText.data(using: .utf8)!)
            print("encripted =\(encripted)")
            let decripted = try cipher.decryptWithAd(authenticationData: ad, ciphertext: encripted)
            print("decrypted =\(decripted)")

            let resStr = String(bytes: decripted, encoding: .utf8)
            print("decrypted str =\(resStr)")
        } catch  {
            print("Error =\(error)")
        }
    }

}
