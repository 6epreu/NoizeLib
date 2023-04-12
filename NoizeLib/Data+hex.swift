//
// Created by Sergey Brazhnik on 31.03.2023.
//

import Foundation

public extension Data {
    var hex : String{
        get {
            let str = map { (element) -> String in
                String(format: "%02x", element)
            }
            return str.joined()
        }
    }

    var bytes: Array<UInt8> {
        Array(self)
    }

    init(hex: String){
        let data = hex.data(using: .utf8)!
        self.init(hexData: data)
    }

    init(hexData : Data) {
        func shift(c : UInt8 ) -> UInt8{
            if c <= 57 {
                return c - 48
            } else if c >= 65 && c <= 70 {
                return c - 55
            } else if c >= 97 {
                return c - 87
            }
            return 0
        }

        var prev : UInt8 = 0
        var current : UInt8 = 0
        var done = false
        var resData = Data()
        for n in 0...hexData.count-1 {
            if !done {
                prev = shift(c: hexData[n])
            } else {
                current = shift(c: hexData[n])
                let old = prev << 4
                let yong = current & 0b00001111
                let combinedbits = old | yong
                resData.append(combinedbits)
            }
            done = !done
        }
        self = resData
    }

    mutating func fillWithZero() {
        if count > 0 {
            self.resetBytes(in: 0...count-1)
        }
    }

    mutating func xor(key: Data) {
        for i in 0..<self.count {
            self[i] ^= key[i % key.count]
        }
    }
}

