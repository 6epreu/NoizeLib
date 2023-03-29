//
// Created by Sergey Brazhnik on 29.03.2023.
//

import Foundation

extension Data {
    static func fromInt(integer: UInt) -> Data {
        var temp = integer
        return Data(bytes: &temp, count: MemoryLayout.size(ofValue: integer))
    }
}