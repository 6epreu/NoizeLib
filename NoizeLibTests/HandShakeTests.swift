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

//        let aliceStaticKey: (public: Data, private: Data) = (
//                Data(hex: "3a58a0af15795c6b5f83a9b2cb3c70d87fb6774b3b9fe75f1845eebe527ab57c"),
//                Data(hex: "245fe71a02be0310b96b1d168286f31f6e6ae6abe8d6287beec0f4c8fdc54e7d")
//        )
//        let aliceEphemeralKey: (public: Data, private: Data) = (
//                Data(hex: "c0954b41a37733996a4c1da6d8a71a71e48863307d9a50efa62ee313a979123c"),
//                Data(hex: "67f7317a385465b049ece565de426ba8e6db3e622b9f6e4729b8de9db235d9c9")
//        )
//        let bobEphemeralKey: (public: Data, private: Data) = (
//                Data(hex: "335a50003e674ea8cbe97590cd43cbc515b7ea55775a7eab19f46b9670b89c38"),
//                Data(hex: "26770c6929565eecfa11e35496ba1560d6d7122e0f7ecbfff8ffdbb61dd947ff")
//        )

        let aliceStaticKey: (public: Data, private: Data) = (
                Data(hex: "1f49cca1bd97b9d17387abf04b8eabd032181e3caf663c878547810cceb8511c"),
                Data(hex: "483eb750f7da39105c24100c848ff2c7653336d499e9ca8f9f711de7cc85ab66")
        )
        let aliceEphemeralKey: (public: Data, private: Data) = (
                Data(hex: "1191a85855e82fa5ec9cf57b9ca3b65edbec9d2696ef21061417d9102c71a103"),
                Data(hex: "981223fd8b2497377f1dd6054e2f425fb5d2b73ee906b7e3d6af092fd8cf7aa8")
        )
        let bobEphemeralKey: (public: Data, private: Data) = (
                Data(hex: "335a50003e674ea8cbe97590cd43cbc515b7ea55775a7eab19f46b9670b89c38"),
                Data(hex: "26770c6929565eecfa11e35496ba1560d6d7122e0f7ecbfff8ffdbb61dd947ff")
        )

        let prologue = Data()

        // initiator
        let EAM = HandshakeStateImpl(pattern: pattern,
                role: .initiator,
                prologue: prologue,
                s: aliceStaticKey,
                e: aliceEphemeralKey,
                rs: nil,
                re: nil)

        // responder
        pattern.keyGenAlgKey.pair
        let EIC = HandshakeStateImpl(pattern: pattern,
                role: .responder,
                prologue: prologue,
                s: nil,
                e: bobEphemeralKey,
                rs: aliceStaticKey.public,
                re: nil)


        //let string01 = "Hello"; let string01Data = string01.data(using: .utf8)!
        let string01 = "0000000099999999"; let string01Data = string01.data(using: .utf8)!
        let string02 = "000000000011111111110000000000111111111100000000001111111111000000000011111111110000000000111111111177"; let string02Data = string02.data(using: .utf8)!
        let voucherResponseBase64 = "EZGoWFXoL6XsnPV7nKO2XtvsnSaW7yEGFBfZECxxoQMUCFwn7M18FAAAAABkULeM".data(using: .utf8)!
        let voucherResponse = Data(base64Encoded: voucherResponseBase64)!
        let string03 = "Bye"; let string03Data = string03.data(using: .utf8)!

        let alice01 = try EAM.writeMessage(payload: string01Data)
        print("alice01.hex = \(alice01.resData.hex)")
        //let bob01 = try EIC.readMessage(payload: alice01.resData)
        let bob01 = try EIC.readMessage(payload: voucherResponse)
        print("bob01.hex = \(bob01.resData.hex)")
        XCTAssertEqual(bob01.resData, string01Data)
        let handshakeHash = EIC.symmetricState.getHandshakeHash()

        let bob02 = try EIC.writeMessage(payload: string02Data)
        print("bob02.hex = \(bob02.resData.hex)")
        let alice02 = try EAM.readMessage(payload: bob02.resData)
        print("alice02.hex = \(alice02.resData.hex)")
        XCTAssertEqual(alice02.resData, string02Data)

        let alice03 = try EAM.writeMessage(payload: string03Data)
        print("alice03.hex = \(alice03.resData.hex)")
        let bob03 = try EIC.readMessage(payload: alice03.resData)
        print("bob03.hex = \(bob03.resData.hex)")
        XCTAssertEqual(bob03.resData, string03Data)
    }

    func testhandShakeNK() throws {
        let pattern = Pattern.Noise_NK_25519_ChaChaPoly_SHA256

        let bobStaticKey: (public: Data, private: Data) = (
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
                s: nil,
                e: aliceEphemeralKey,
                rs: bobStaticKey.public,
                re: nil)

        // responder
        let bob = HandshakeStateImpl(pattern: pattern,
                role: .responder,
                prologue: prologue,
                s: bobStaticKey,
                e: bobEphemeralKey,
                rs: nil,
                re: nil)


        let string01 = "Hello"; let string01Data = string01.data(using: .utf8)!
        let string02 = "Hi"; let string02Data = string02.data(using: .utf8)!
        let string03 = "Bye"; let string03Data = string03.data(using: .utf8)!

        let alice01 = try alice.writeMessage(payload: string01Data)
        print("alice01.hex = \(alice01.resData.hex)")
        let bob01 = try bob.readMessage(payload: alice01.resData)
        print("bob01.hex = \(bob01.resData.hex)")
        XCTAssertEqual(bob01.resData, string01Data)
        bob.symmetricState.getHandshakeHash()

        let bob02 = try bob.writeMessage(payload: string02Data)
        print("bob02.hex = \(bob02.resData.hex)")
        let alice02 = try alice.readMessage(payload: bob02.resData)
        print("alice02.hex = \(alice02.resData.hex)")
        XCTAssertEqual(alice02.resData, string02Data)

        guard let aliceTransport = alice02.transport else {
            return
        }

        let encryptedRes = try aliceTransport.responderCipher.encryptWithAd(authenticationData: Data(), plaintext: string03Data)

        guard let bobTransport = bob02.transport else {
            return
        }

        let decriptedRes = try bobTransport.responderCipher.decryptWithAd(authenticationData: Data(), ciphertext: encryptedRes)

        XCTAssertEqual(decriptedRes,string03Data)
    }

}
