//
//  ADRS.swift
//  SwiftFIPS205Test
//
//  Created by Leif Ibsen on 25/11/2023.
//

struct ADRS {
    
    static let WOTS_HASH = 0
    static let WOTS_PK = 1
    static let TREE = 2
    static let FORS_TREE = 3
    static let FORS_ROOTS = 4
    static let WOTS_PRF = 5
    static let FORS_PRF = 6

    var adrs: Words
    
    init() {
        self.adrs = Words(repeating: 0, count: 8)
    }

    var bytes: Bytes { get {
        var x = Bytes(repeating: 0, count: 32)
        x[0] = Byte(self.adrs[0] >> 24 & 0xff)
        x[1] = Byte(self.adrs[0] >> 16 & 0xff)
        x[2] = Byte(self.adrs[0] >>  8 & 0xff)
        x[3] = Byte(self.adrs[0] >>  0 & 0xff)
        x[4] = Byte(self.adrs[1] >> 24 & 0xff)
        x[5] = Byte(self.adrs[1] >> 16 & 0xff)
        x[6] = Byte(self.adrs[1] >>  8 & 0xff)
        x[7] = Byte(self.adrs[1] >>  0 & 0xff)
        x[8] = Byte(self.adrs[2] >> 24 & 0xff)
        x[9] = Byte(self.adrs[2] >> 16 & 0xff)
        x[10] = Byte(self.adrs[2] >>  8 & 0xff)
        x[11] = Byte(self.adrs[2] >>  0 & 0xff)
        x[12] = Byte(self.adrs[3] >> 24 & 0xff)
        x[13] = Byte(self.adrs[3] >> 16 & 0xff)
        x[14] = Byte(self.adrs[3] >>  8 & 0xff)
        x[15] = Byte(self.adrs[3] >>  0 & 0xff)
        x[16] = Byte(self.adrs[4] >> 24 & 0xff)
        x[17] = Byte(self.adrs[4] >> 16 & 0xff)
        x[18] = Byte(self.adrs[4] >>  8 & 0xff)
        x[19] = Byte(self.adrs[4] >>  0 & 0xff)
        x[20] = Byte(self.adrs[5] >> 24 & 0xff)
        x[21] = Byte(self.adrs[5] >> 16 & 0xff)
        x[22] = Byte(self.adrs[5] >>  8 & 0xff)
        x[23] = Byte(self.adrs[5] >>  0 & 0xff)
        x[24] = Byte(self.adrs[6] >> 24 & 0xff)
        x[25] = Byte(self.adrs[6] >> 16 & 0xff)
        x[26] = Byte(self.adrs[6] >>  8 & 0xff)
        x[27] = Byte(self.adrs[6] >>  0 & 0xff)
        x[28] = Byte(self.adrs[7] >> 24 & 0xff)
        x[29] = Byte(self.adrs[7] >> 16 & 0xff)
        x[30] = Byte(self.adrs[7] >>  8 & 0xff)
        x[31] = Byte(self.adrs[7] >>  0 & 0xff)
        return x
    } }

    func getLayerAddress() -> Int {
        return Int(self.adrs[0])
    }
    
    mutating func setLayerAddress(_ x: Int) {
        self.adrs[0] = Word(x)
    }

    func getTreeAddress() -> Int {
        return Int(self.adrs[2]) << 32 | Int(self.adrs[3])
    }
    
    mutating func setTreeAddress(_ x: Int) {
        self.adrs[1] = 0
        self.adrs[2] = Word((x >> 32) & 0xffffffff)
        self.adrs[3] = Word(x & 0xffffffff)
    }

    func getType() -> Int {
        return Int(self.adrs[4])
    }
    
    mutating func setTypeAndClear(_ x: Int) {
        self.adrs[4] = Word(x)
        self.adrs[5] = 0
        self.adrs[6] = 0
        self.adrs[7] = 0
    }

    func getKeyPairAddress() -> Int {
        return Int(self.adrs[5])
    }
    
    mutating func setKeyPairAddress(_ x: Int) {
        self.adrs[5] = Word(x)
    }

    func getChainAddress() -> Int {
        return Int(self.adrs[6])
    }
    
    mutating func setChainAddress(_ x: Int) {
        self.adrs[6] = Word(x)
    }

    func getTreeHeight() -> Int {
        return Int(self.adrs[6])
    }
    
    mutating func setTreeHeight(_ x: Int) {
        self.adrs[6] = Word(x)
    }

    func getHashAddress() -> Int {
        return Int(self.adrs[7])
    }
    
    mutating func setHashAddress(_ x: Int) {
        self.adrs[7] = Word(x)
    }

    func getTreeIndex() -> Int {
        return Int(self.adrs[7])
    }
    
    mutating func setTreeIndex(_ x: Int) {
        self.adrs[7] = Word(x)
    }

    func compress() -> Bytes {
        var x = Bytes(repeating: 0, count: 22)
        x[0] = Byte(self.adrs[0] & 0xff)
        x[1] = Byte((self.adrs[2] >> 24) & 0xff)
        x[2] = Byte((self.adrs[2] >> 16) & 0xff)
        x[3] = Byte((self.adrs[2] >> 8) & 0xff)
        x[4] = Byte((self.adrs[2] >> 0) & 0xff)
        x[5] = Byte((self.adrs[3] >> 24) & 0xff)
        x[6] = Byte((self.adrs[3] >> 16) & 0xff)
        x[7] = Byte((self.adrs[3] >> 8) & 0xff)
        x[8] = Byte((self.adrs[3] >> 0) & 0xff)
        x[9] = Byte(self.adrs[4] & 0xff)
        x[10] = Byte((self.adrs[5] >> 24) & 0xff)
        x[11] = Byte((self.adrs[5] >> 16) & 0xff)
        x[12] = Byte((self.adrs[5] >> 8) & 0xff)
        x[13] = Byte((self.adrs[5] >> 0) & 0xff)
        x[14] = Byte((self.adrs[6] >> 24) & 0xff)
        x[15] = Byte((self.adrs[6] >> 16) & 0xff)
        x[16] = Byte((self.adrs[6] >> 8) & 0xff)
        x[17] = Byte((self.adrs[6] >> 0) & 0xff)
        x[18] = Byte((self.adrs[7] >> 24) & 0xff)
        x[19] = Byte((self.adrs[7] >> 16) & 0xff)
        x[20] = Byte((self.adrs[7] >> 8) & 0xff)
        x[21] = Byte((self.adrs[7] >> 0) & 0xff)
        return x
    }
    
}
