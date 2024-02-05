//
//  DRBG.swift
//  KATGen
//
//  Created by Leif Ibsen on 08/12/2023.
//

@testable import SwiftSPHINCS

// NIST 800-90A

class DRBG {
    
    var key = Bytes(repeating: 0, count: 32)
    var ctr = Bytes(repeating: 0, count: 16)
    
    convenience init() {
        var seed = Bytes(repeating: 0, count: 48)
        for i in 0 ..< 48 {
            seed[i] = Byte(i)
        }
        self.init(seed)
    }

    init(_ seed: Bytes) {
        self.update(seed)
    }

    func update(_ data: Bytes) {
        var temp: Bytes = []
        let aes = AES(self.key)
        while temp.count < 48 {
            self.incrementCtr()
            var x = self.ctr
            aes.encrypt(&x)
            temp += x
        }
        for i in 0 ..< 48 {
            temp[i] ^= data[i]
        }
        self.key = Bytes(temp[0 ..< 32])
        self.ctr = Bytes(temp[32 ..< 48])
    }

    func update() {
        var temp: Bytes = []
        let aes = AES(self.key)
        while temp.count < 48 {
            self.incrementCtr()
            var x = self.ctr
            aes.encrypt(&x)
            temp += x
        }
        self.key = Bytes(temp[0 ..< 32])
        self.ctr = Bytes(temp[32 ..< 48])
    }

    func incrementCtr() {
        for i in (0 ..< 16).reversed() {
            if self.ctr[i] == 0xff {
                self.ctr[i] = 0
            } else {
                self.ctr[i] += 1
                break
            }
        }
    }
    
    func randomBytes(_ n: Int) -> Bytes {
        var temp: Bytes = []
        let aes = AES(self.key)
        while temp.count < n {
            self.incrementCtr()
            var x = self.ctr
            aes.encrypt(&x)
            temp += x
        }
        self.update()
        return Bytes(temp[0 ..< n])
    }

}
