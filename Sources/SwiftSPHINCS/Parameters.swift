//
//  File.swift
//  
//
//  Created by Leif Ibsen on 19/10/2023.
//

// Parameters for the six instances
struct Parameters {
    
    let n: Int
    let h: Int
    let d: Int
    let h1: Int
    let a: Int
    let k: Int
    let lgw: Int
    let m: Int
    let mdSize: Int
    let treeSize: Int
    let leafSize: Int
    let treeMask: Int
    let leafMask: Int
    let w: Int
    let len: Int
    let len1: Int
    let len2: Int
    
    // Figures from [FIPS205] section 10

    // P1 parameters
    static let P1 =  Parameters(n: 16, h: 63, d:  7, h1: 9, a: 12, k: 14, lgw: 4, m: 30,
                                mdSize: 21, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
                                leafMask: 0x1ff, w: 16, len: 35, len1: 32, len2: 3)
    
    // P2 parameters
    static let P2 =  Parameters(n: 16, h: 66, d: 22, h1: 3, a:  6, k: 33, lgw: 4, m: 34,
                                mdSize: 25, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
                                leafMask: 0x7, w: 16, len: 35, len1: 32, len2: 3)
    
    // P3 parameters
    static let P3 =  Parameters(n: 24, h: 63, d:  7, h1: 9, a: 14, k: 17, lgw: 4, m: 39,
                                mdSize: 30, treeSize: 7, leafSize: 2, treeMask: 0x3fffffffffffff,
                                leafMask: 0x1ff, w: 16, len: 51, len1: 48, len2: 3)
    
    // P4 parameters
    static let P4 =  Parameters(n: 24, h: 66, d: 22, h1: 3, a:  8, k: 33, lgw: 4, m: 42,
                                mdSize: 33, treeSize: 8, leafSize: 1, treeMask: 0x7fffffffffffffff,
                                leafMask: 0x7, w: 16, len: 51, len1: 48, len2: 3)
    
    // P5 parameters
    static let P5 =  Parameters(n: 32, h: 64, d:  8, h1: 8, a: 14, k: 22, lgw: 4, m: 47,
                                mdSize: 39, treeSize: 7, leafSize: 1, treeMask: 0xffffffffffffff,
                                leafMask: 0xff, w: 16, len: 67, len1: 64, len2: 3)
    
    // P6 parameters
    static let P6 =  Parameters(n: 32, h: 68, d: 17, h1: 4, a:  9, k: 35, lgw: 4, m: 49,
                                mdSize: 40, treeSize: 8, leafSize: 1, treeMask: -1,
                                leafMask: 0xf, w: 16, len: 67, len1: 64, len2: 3)

    static func n(_ kind: SPHINCSKind) -> Int {
        switch kind {
        case .SHA2_128s, .SHAKE_128s, .SHA2_128f, .SHAKE_128f:
            return 16
        case .SHA2_192s, .SHAKE_192s, .SHA2_192f, .SHAKE_192f:
            return 24
        case .SHA2_256s, .SHAKE_256s, .SHA2_256f, .SHAKE_256f:
            return 32
        }
    }
}
