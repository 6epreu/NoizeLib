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

class HandshakeTests: XCTestCase {

    override func setUpWithError() throws {
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }

    override func tearDownWithError() throws {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
    }

    func testhandShakeXN() throws {
        let pattern = Pattern.Noise_XN_25519_ChaChaPoly_SHA256
        //let aliceStaticKey = pattern.keyGenAlgKey.pair



        let aliceStaticKey: (public: Data, private: Data) = (
                Data(hex: "3a58a0af15795c6b5f83a9b2cb3c70d87fb6774b3b9fe75f1845eebe527ab57c"),
                Data(hex: "245fe71a02be0310b96b1d168286f31f6e6ae6abe8d6287beec0f4c8fdc54e7d")
        )
        let aliceEphemeralKey: (public: Data, private: Data) = (
                Data(hex: "c0954b41a37733996a4c1da6d8a71a71e48863307d9a50efa62ee313a979123c"),
                Data(hex: "67f7317a385465b049ece565de426ba8e6db3e622b9f6e4729b8de9db235d9c9")
        )
        let bobEphemeralKey: (public: Data, private: Data) = (
                Data(hex: "335a50003e674ea8cbe97590cd43cbc515b7ea55775a7eab19f46b9670b89c38"),
                Data(hex: "26770c6929565eecfa11e35496ba1560d6d7122e0f7ecbfff8ffdbb61dd947ff")
        )

        let prologue = Data()

        // initiator
        let alice = HandshakeStateImpl(pattern: pattern,
                role: .initiator,
                prologue: prologue,
                s: aliceStaticKey,
                e: aliceEphemeralKey,
                rs: nil,
                re: nil)

        // responder
        let bob = HandshakeStateImpl(pattern: pattern,
                role: .responder,
                prologue: prologue,
                s: nil,
                e: bobEphemeralKey,
                rs: aliceStaticKey.public,
                re: nil)


        let string01 = "Hello"; let string01Data = string01.data(using: .utf8)!
        let string02 = "Hi"; let string02Data = string02.data(using: .utf8)!
        let string03 = "Bye"; let string03Data = string03.data(using: .utf8)!

        let alice01 = try alice.writeMessage(payload: string01Data)
        print("alice01.hex = \(alice01.resData.hex)")
        let bob01 = try bob.readMessage(payload: alice01.resData)
        print("bob01.hex = \(bob01.resData.hex)")
        XCTAssertEqual(bob01.resData, string01Data)

        let bob02 = try bob.writeMessage(payload: string02Data)
        print("bob02.hex = \(bob02.resData.hex)")
        let alice02 = try alice.readMessage(payload: bob02.resData)
        print("alice02.hex = \(alice02.resData.hex)")
        XCTAssertEqual(alice02.resData, string02Data)

        let alice03 = try alice.writeMessage(payload: string03Data)
        print("alice03.hex = \(alice03.resData.hex)")
        let bob03 = try bob.readMessage(payload: alice03.resData)
        print("bob03.hex = \(bob03.resData.hex)")
        XCTAssertEqual(bob03.resData, string03Data)
    }
}
