//
// Created by Sergey Brazhnik on 17.04.2023.
//

import Foundation

enum HandShakeErrors: Error {
    case invalidArgument(String)
}

enum ROLE {
    case initiator
    case responder
}

protocol HandshakeState {
    var s: (public: Data, private: Data)? { get }     // The local static key pair
    var e: (public: Data, private: Data)? { get }     // The local ephemeral key pair
    var rs: Data? { get }    // The remote party's static key pair
    var re: Data? { get }    // The remote party's ephemeral key pair
    var symmetricState: SymmetricState { get }        // symmetry stata
    var initiator: Bool { get }                       // A boolean indicating the initiator or responder role.
    var role: ROLE { get }                            // Initiator or responder
    var messagePatterns: [[Token]] { get }              // A sequence of message patterns.

    init(pattern: Pattern,
         role: ROLE,
         prologue: Data,
         s: (public: Data, private: Data)?,
         e: (public: Data, private: Data)?,
         rs: Data?,
         re: Data?)

    func writeMessage(payload: Data) throws -> (state: HandshakeState, transport: Transport?, resData: Data)
    func readMessage(payload: Data) throws -> (state: HandshakeState, transport: Transport?, resData: Data)
}

class HandshakeStateImpl: HandshakeState {
    private(set) var s: (public: Data, private: Data)? = nil
    private(set) var e: (public: Data, private: Data)? = nil
    private(set) var rs: Data? = nil
    private(set) var re: Data? = nil
    private(set) var symmetricState: SymmetricState
    internal var initiator: Bool {
        get {
            self.role == ROLE.initiator
        }
    }
    private(set) var role: ROLE
    private(set) var messagePatterns: [[Token]] = [[]]

    private var pattern: Pattern

    required init(pattern: Pattern,
                  role: ROLE,
                  prologue: Data,
                  s: (public: Data, private: Data)?,
                  e: (public: Data, private: Data)?,
                  rs: Data? = nil,
                  re: Data? = nil) {
        self.role = role
        self.pattern = pattern
        self.s = s
        self.e = e
        self.rs = rs
        self.re = re
        self.messagePatterns = pattern.messagePatterns
        symmetricState = SymmetricStateImpl(pattern: pattern)
        symmetricState.mixHash(data: prologue)

        if initiator {
            for token in pattern.preSharedMessagePatternsInitiator {
                if token == .S, let s = s {
                    symmetricState.mixHash(data: s.public);
                }
            }
            for token in pattern.preSharedMessagePatternsResponder {
                if token == .S, let rs = rs {
                    symmetricState.mixHash(data: rs);
                }
            }
        } else {
            for token in pattern.preSharedMessagePatternsInitiator {
                if token == .S, let rs = rs {
                    symmetricState.mixHash(data: rs);
                }
            }
            for token in pattern.preSharedMessagePatternsResponder {
                if token == .S, let s = s {
                    symmetricState.mixHash(data: s.public);
                }
            }
        }
    }


    func mix(local: Data?, remote: Data?, token: Token) throws -> Data {
        guard let local = local else { throw HandShakeErrors.invalidArgument("No local provided while handling \(token) token") }
        guard let remote = remote else { throw HandShakeErrors.invalidArgument("No remote provided while handling \(token) token") }
        return try pattern.dhAlg(local, remote)
    }

    func writeMessage(payload: Data) throws -> (state: HandshakeState, transport: Transport?, resData: Data) {
        var buffer = Data()

        // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
        if messagePatterns.count > 0 {
            let nextTokensList = messagePatterns.removeFirst()

            for token in nextTokensList {
                print("writeMessage token = \(token)")
                switch token {
                case .E:
                    guard let e = e else { throw HandShakeErrors.invalidArgument("No e provided while handling E token") }
                    buffer = buffer + e.public
                    symmetricState.mixHash(data: e.public)
                case .S:
                    guard let s = s else { throw HandShakeErrors.invalidArgument("No s provided while handling S token") }
                    buffer = buffer + symmetricState.encryptAndHash(plainText: s.public)
                case .EE:
                    let dhRes = try mix(local: e?.private, remote: re, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)
                case .ES:
                    let dhRes = initiator ? try mix(local: e?.private, remote: rs, token: token) : try mix(local: s?.private, remote: re, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)
                case .SE:
                    let dhRes = initiator ? try mix(local: s?.private, remote: re, token: token) : try mix(local: e?.private, remote: rs, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)
                case .SS:
                    let dhRes = try mix(local: s?.private, remote: rs, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)

                default: ""
                }
            }

            // Appends EncryptAndHash(payload) to the buffer.
            buffer = buffer + symmetricState.encryptAndHash(plainText: payload)
        }

        // If there are no more message patterns returns two new CipherState objects by calling Split()
        if messagePatterns.isEmpty {
            let cipherPairs = symmetricState.split()
            let transport = Transport(initiatorCipher: cipherPairs.0, responderCipher: cipherPairs.1, handShakeHash: symmetricState.h)
            return (state: self, transport: transport, resData: buffer)
        } else {
            return (state: self, transport: nil, resData: buffer)
        }
    }

    func readMessage(payload: Data) throws -> (state: HandshakeState, transport: Transport?, resData: Data) {
        var buffer = payload
        var output = Data()

        func read(size: Int, payload: inout Data ) -> Data {
            let range = 0..<size
            let toReturn = payload.subdata(in: range)
            payload.replaceSubrange(range, with: Data())
            return toReturn
        }

        // Fetches and deletes the next message pattern from message_patterns, then sequentially processes each token from the message pattern:
        if messagePatterns.count > 0 {
            let nextTokensList = messagePatterns.removeFirst()

            for token in nextTokensList {
                print("ReadMessage token = \(token) dataToRead =  \(buffer.hex)")
                switch token {
                case .E:
                    re = read(size: pattern.DHLEN, payload: &buffer)
                    symmetricState.mixHash(data: re!)
                case .S:
                    var temp: Data
                    if symmetricState.cipher.hasKey() {
                        temp = read(size: pattern.DHLEN + 16, payload: &buffer)
                    } else {
                        temp = read(size: pattern.DHLEN, payload: &buffer)
                    }
                    print("readMessage to decrypt " + temp.hex)
                    rs = symmetricState.decryptAndHash(cipherText: temp)

                case .EE:
                    let dhRes = try mix(local: e?.private, remote: re, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)

                case .ES:
                    let dhRes = initiator ? try mix(local: e?.private, remote: rs, token: token) : try mix(local: s?.private, remote: re, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)

                case .SE:
                    let dhRes = initiator ? try mix(local: s?.private, remote: re, token: token) : try mix(local: e?.private, remote: rs, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)

                case .SS:
                    let dhRes = try mix(local: s?.private, remote: rs, token: token)
                    symmetricState.mixKey(inputKeyMaterial: dhRes)


                default: ""
                }
            }

            // Appends EncryptAndHash(payload) to the buffer.
            output = symmetricState.decryptAndHash(cipherText: buffer)

        }

        // If there are no more message patterns returns two new CipherState objects by calling Split()
        if messagePatterns.isEmpty {
            let cipherPairs = symmetricState.split()
            let transport = Transport(initiatorCipher: cipherPairs.0, responderCipher: cipherPairs.1, handShakeHash: symmetricState.h)
            return (state: self, transport: transport, resData: output)
        } else {
            return (state: self, transport: nil, resData: output)
        }
    }
}
