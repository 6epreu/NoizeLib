//
// Created by Sergey Brazhnik on 25.04.2023.
//

import Foundation

struct Transport {
    let initiatorCipher : CipherState
    let responderCipher : CipherState
    let handShakeHash : Data
}