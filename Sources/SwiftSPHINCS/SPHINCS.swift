//
//  SPHINCS.swift
//  Slice
//
//  Created by Leif Ibsen on 10/12/2023.
//

import Foundation
import Digest

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

typealias Word = UInt32
typealias Words = [UInt32]

/// The SPHINCS structure
public struct SPHINCS {
    
    static func randomBytes(_ bytes: inout Bytes) {
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            fatalError("randomBytes failed")
        }
    }
    
    let kind: SPHINCSKind
    let shake256: SHAKE
    let sha256: MessageDigest
    let sha512: MessageDigest
    let param: Parameters
    
    // MARK: Initializer
    
    /// Constructs a SPHINCS instance of a specified kind
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    public init(kind: SPHINCSKind) {
        self.kind = kind
        switch kind {
        case .SHA2_128s, .SHAKE_128s:
            self.param = Parameters.P1
        case .SHA2_128f, .SHAKE_128f:
            self.param = Parameters.P2
        case .SHA2_192s, .SHAKE_192s:
            self.param = Parameters.P3
        case .SHA2_192f, .SHAKE_192f:
            self.param = Parameters.P4
        case .SHA2_256s, .SHAKE_256s:
            self.param = Parameters.P5
        case .SHA2_256f, .SHAKE_256f:
            self.param = Parameters.P6
        }
        self.shake256 = SHAKE(.SHAKE256)
        self.sha256 = MessageDigest(.SHA2_256)
        self.sha512 = MessageDigest(.SHA2_512)
    }
    
    
    // MARK: Methods
    
    /// Generates a secret key and a public key
    ///
    /// - Returns: The secret key `sk` and the public key `pk`
    public func GenerateKeyPair() -> (sk: SecretKey, pk: PublicKey) {
        let (sk, pk) = slhKeyGen()
        do {
            return (try SecretKey(kind: self.kind, keyBytes: sk), try PublicKey(kind: self.kind, keyBytes: pk))
        } catch {
            // Shouldn't happen
            fatalError("GenerateKeyPair inconsistency")
        }
    }
    
    func Trunc(_ x: Bytes) -> Bytes {
        return Bytes(x[0 ..< self.param.n])
    }
    
    func Hmsg(_ R: Bytes, _ PKseed: Bytes, _ PKroot: Bytes, _ M: Bytes) -> Bytes {
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(R)
            self.shake256.update(PKseed)
            self.shake256.update(PKroot)
            self.shake256.update(M)
            return self.shake256.digest(self.param.m)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(R)
            self.sha256.update(PKseed)
            self.sha256.update(PKroot)
            self.sha256.update(M)
            return KDF.MGF1(.SHA2_256, R + PKseed + self.sha256.digest(), self.param.m)
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(R)
            self.sha512.update(PKseed)
            self.sha512.update(PKroot)
            self.sha512.update(M)
            return KDF.MGF1(.SHA2_512, R + PKseed + self.sha512.digest(), self.param.m)
        }
    }
    
    func PRF(_ PKseed: Bytes, _ SKseed: Bytes, _ adrs: ADRS) -> Bytes {
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(SKseed)
            return self.shake256.digest(self.param.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(SKseed)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(SKseed)
            return Trunc(self.sha256.digest())
        }
    }
    
    func PRFmsg(_ SKprf: Bytes, _ optRand: Bytes, _ M: Bytes) -> Bytes {
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(SKprf)
            self.shake256.update(optRand)
            self.shake256.update(M)
            return self.shake256.digest(self.param.n)
        case .SHA2_128s, .SHA2_128f:
            let hmac = HMAC(.SHA2_256, SKprf)
            hmac.update(optRand)
            hmac.update(M)
            return Trunc(hmac.compute())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            let hmac = HMAC(.SHA2_512, SKprf)
            hmac.update(optRand)
            hmac.update(M)
            return Trunc(hmac.compute())
        }
    }
    
    func F(_ PKseed: Bytes, _ adrs: ADRS, _ M1: Bytes) -> Bytes {
        assert(M1.count == self.param.n)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M1)
            return self.shake256.digest(self.param.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M1)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M1)
            return Trunc(self.sha256.digest())
        }
    }
    
    func H(_ PKseed: Bytes, _ adrs: ADRS, _ M2: Bytes) -> Bytes {
        assert(M2.count == self.param.n << 1)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M2)
            return self.shake256.digest(self.param.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M2)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(PKseed)
            self.sha512.update(toByte(0, 128 - self.param.n))
            self.sha512.update(adrs.compress())
            self.sha512.update(M2)
            return Trunc(self.sha512.digest())
        }
    }
    
    func T(_ PKseed: Bytes, _ adrs: ADRS, _ M: Bytes) -> Bytes {
        assert(M.count % self.param.n == 0)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M)
            return self.shake256.digest(self.param.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.param.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(PKseed)
            self.sha512.update(toByte(0, 128 - self.param.n))
            self.sha512.update(adrs.compress())
            self.sha512.update(M)
            return Trunc(self.sha512.digest())
        }
    }
    
    // [FIPS 205] - Algorithm 1
    func toInt(_ X: Bytes, _ n: Int) -> Int {
        assert(X.count == n)
        var total = 0
        for i in 0 ..< n {
            total = total << 8 | Int(X[i])
        }
        return total
    }
    
    // [FIPS 205] - Algorithm 2
    func toByte(_ x: Int, _ n: Int) -> Bytes {
        var S = Bytes(repeating: 0, count: n)
        var total = x
        for i in 0 ..< n {
            S[n - 1 - i] = Byte(total & 0xff)
            total >>= 8
        }
        return S
    }
    
    // [FIPS 205] - Algorithm 3
    func base2b(_ X: Bytes, _ b: Int, _ outLen: Int) -> [Int] {
        assert(X.count >= (outLen * b + 7) >> 3)
        var baseb = [Int](repeating: 0, count: outLen)
        let bMask = (1 << b) - 1
        var in_ = 0
        var bits = 0
        var total = 0
        for out in 0 ..< outLen {
            while bits < b {
                total = total << 8 | Int(X[in_])
                in_ += 1
                bits += 8
            }
            bits -= b
            baseb[out] = (total >> bits) & bMask
        }
        return baseb
    }
    
    // [FIPS 205] - Algorithm 4
    func chain(_ X: Bytes, _ i: Int , _ s: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(PKseed.count == self.param.n)
        var adrs = adrs
        if i + s >= self.param.w {
            return []
        }
        var tmp = X
        for j in i ..< i + s {
            adrs.setHashAddress(j)
            tmp = F(PKseed, adrs, tmp)
        }
        return tmp
    }
    
    // [FIPS 205] - Algorithm 5
    func wotsPKgen(_ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var skADRS = adrs
        skADRS.setType(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        var tmp: Bytes = []
        for i in 0 ..< self.param.len {
            skADRS.setChainAddress(i)
            let sk = PRF(PKseed, SKseed, skADRS)
            adrs.setChainAddress(i)
            tmp += chain(sk, 0, self.param.w - 1, PKseed, adrs)
        }
        var wotspkADRS = adrs
        wotspkADRS.setType(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        return T(PKseed, wotspkADRS, tmp)
    }
    
    // [FIPS 205] - Algorithm 6
    func wotsSign(_ M: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(M.count == self.param.n)
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var csum = 0
        var sig: Bytes = []
        var msg = base2b(M, self.param.lgw, self.param.len1)
        for i in 0 ..< self.param.len1 {
            csum += self.param.w - 1 - msg[i]
        }
        csum <<= 4
        msg += base2b(toByte(csum, 2), self.param.lgw, self.param.len2)
        var skADRS = adrs
        skADRS.setType(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        for i in 0 ..< self.param.len {
            skADRS.setChainAddress(i)
            let sk = PRF(PKseed, SKseed, skADRS)
            adrs.setChainAddress(i)
            sig += chain(sk, 0, msg[i], PKseed, adrs)
        }
        assert(sig.count == self.param.n * self.param.len)
        return sig
    }
    
    // [FIPS 205] - Algorithm 7
    func wotsPKFromSig(_ sig: Bytes, _ M: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(sig.count == self.param.n * self.param.len)
        assert(M.count == self.param.n)
        assert(PKseed.count == self.param.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var csum = 0
        var msg = base2b(M, self.param.lgw, self.param.len1)
        for i in 0 ..< self.param.len1 {
            csum += self.param.w - 1 - msg[i]
        }
        csum <<= 4
        msg += base2b(toByte(csum, 2), self.param.lgw, self.param.len2)
        var tmp: Bytes = []
        var sigSlice = sig.sliced()
        for i in 0 ..< self.param.len {
            adrs.setChainAddress(i)
            tmp += chain(sigSlice.next(self.param.n), msg[i], self.param.w - 1 - msg[i], PKseed, adrs)
        }
        var wotspkADRS = adrs
        wotspkADRS.setType(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        return T(PKseed, wotspkADRS, tmp)
    }
    
    // [FIPS 205] - Algorithm 8
    func xmssNode(_ SKseed: Bytes, _ i: Int, _ z: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var adrs = adrs
        if z > self.param.h1 || i >= 1 << (self.param.h1 - z) {
            return []
        }
        if z == 0 {
            adrs.setType(ADRS.WOTS_HASH)
            adrs.setKeyPairAddress(i)
            return wotsPKgen(SKseed, PKseed, adrs)
        } else {
            let lnode = xmssNode(SKseed, i << 1, z - 1, PKseed, adrs)
            let rnode = xmssNode(SKseed, i << 1 + 1, z - 1, PKseed, adrs)
            adrs.setType(ADRS.TREE)
            adrs.setTreeHeight(z)
            adrs.setTreeIndex(i)
            return H(PKseed, adrs, lnode + rnode)
        }
    }
    
    // [FIPS 205] - Algorithm 9
    func xmssSign(_ M: Bytes, _ SKseed: Bytes, _ idx: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(M.count == self.param.n)
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        assert(idx >= 0)
        var adrs = adrs
        var AUTH: Bytes = []
        for j in 0 ..< self.param.h1 {
            let k = (idx >> j) ^ 1
            AUTH += xmssNode(SKseed, k, j, PKseed, adrs)
        }
        adrs.setType(ADRS.WOTS_HASH)
        adrs.setKeyPairAddress(idx)
        let sig = wotsSign(M, SKseed, PKseed, adrs)
        let SIGxmss = sig + AUTH
        assert(SIGxmss.count == self.param.n * (self.param.len + self.param.h1))
        return SIGxmss
    }
    
    // [FIPS 205] - Algorithm 10
    func xmssPKFromSig(_ idx: Int, _ SIGxmss: Bytes, _ M: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SIGxmss.count == (self.param.len + self.param.h1) * self.param.n)
        assert(M.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var adrs = adrs
        adrs.setType(ADRS.WOTS_HASH)
        adrs.setKeyPairAddress(idx)
        var SIGxmssSlice = SIGxmss.sliced()
        
        let sig = SIGxmssSlice.next(self.param.len * self.param.n)
        var node0 = wotsPKFromSig(sig, M, PKseed, adrs)
        var node1: Bytes
        adrs.setType(ADRS.TREE)
        adrs.setTreeIndex(idx)
        for k in 0 ..< self.param.h1 {
            adrs.setTreeHeight(k + 1)
            if (idx >> k) & 1 == 0 {
                adrs.setTreeIndex(adrs.getTreeIndex() >> 1)
                node1 = H(PKseed, adrs, node0 + SIGxmssSlice.next(self.param.n))
            } else {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1)
                node1 = H(PKseed, adrs, SIGxmssSlice.next(self.param.n) + node0)
            }
            node0 = node1
        }
        return node0
    }
    
    // [FIPS 205] - Algorithm 11
    func htSign(_ M: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ idxTree: Int, _ idxLeaf: Int) -> Bytes {
        assert(M.count == self.param.n)
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var idxTree = idxTree
        var idxLeaf = idxLeaf
        var adrs = ADRS()
        adrs.setTreeAddress(idxTree)
        var SIGtmp = xmssSign(M, SKseed, idxLeaf, PKseed, adrs)
        var SIGht = SIGtmp
        var root = xmssPKFromSig(idxLeaf, SIGtmp, M, PKseed, adrs)
        let mask1 = 1 << self.param.h1 - 1
        let mask2 = 1 << (64 - self.param.h1) - 1
        for j in 1 ..< self.param.d {
            idxLeaf = idxTree & mask1
            idxTree = (idxTree >> self.param.h1) & mask2
            adrs.setLayerAddress(j)
            adrs.setTreeAddress(idxTree)
            SIGtmp = xmssSign(root, SKseed, idxLeaf, PKseed, adrs)
            SIGht += SIGtmp
            if j < self.param.d - 1 {
                root = xmssPKFromSig(idxLeaf, SIGtmp, root, PKseed, adrs)
            }
        }
        return SIGht
    }
    
    // [FIPS 205] - Algorithm 12
    func htVerify(_ M: Bytes, _ SIGht: Bytes, _ PKseed: Bytes, _ idxTree: Int, _ idxLeaf: Int, _ PKroot: Bytes) -> Bool {
        assert(M.count == self.param.n)
        assert(SIGht.count == (self.param.h + self.param.d * self.param.len) * self.param.n)
        assert(PKseed.count == self.param.n)
        assert(PKroot.count == self.param.n)
        var idxTree = idxTree
        var idxLeaf = idxLeaf
        var adrs = ADRS()
        adrs.setTreeAddress(idxTree)
        var SIGhtSlice = SIGht.sliced()
        let l = (self.param.h1 + self.param.len) * self.param.n
        var node = xmssPKFromSig(idxLeaf, SIGhtSlice.next(l), M, PKseed, adrs)
        let mask1 = (1 << self.param.h1 - 1)
        let mask2 = (1 << (64 - self.param.h1) - 1)
        for j in 1 ..< self.param.d {
            idxLeaf = idxTree & mask1
            idxTree = (idxTree >> self.param.h1) & mask2
            adrs.setLayerAddress(j)
            adrs.setTreeAddress(idxTree)
            node = xmssPKFromSig(idxLeaf, SIGhtSlice.next(l), node, PKseed, adrs)
        }
        return node == PKroot
    }
    
    // [FIPS 205] - Algorithm 13
    func forsSKgen(_ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS, _ idx: Int) -> Bytes {
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var skAdrs = adrs
        skAdrs.setType(ADRS.FORS_PRF)
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
        skAdrs.setTreeIndex(idx)
        return PRF(PKseed, SKseed, skAdrs)
    }
    
    // [FIPS 205] - Algorithm 14
    func forsNode(_ SKseed: Bytes, _ i: Int, _ z: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var adrs = adrs
        if z > self.param.a || i >= self.param.k * (1 << (self.param.a - z)) {
            return []
        }
        if z == 0 {
            let sk = forsSKgen(SKseed, PKseed, adrs, i)
            adrs.setTreeHeight(0)
            adrs.setTreeIndex(i)
            return F(PKseed, adrs, sk)
        } else {
            let lnode = forsNode(SKseed, i << 1, z - 1, PKseed, adrs)
            let rnode = forsNode(SKseed, i << 1 + 1, z - 1, PKseed, adrs)
            adrs.setTreeHeight(z)
            adrs.setTreeIndex(i)
            return H(PKseed, adrs, lnode + rnode)
        }
    }
    
    // [FIPS 205] - Algorithm 15
    func forsSign(_ md: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.param.n)
        assert(PKseed.count == self.param.n)
        var SIGfors: Bytes = []
        let indices = base2b(md, self.param.a, self.param.k)
        for i in 0 ..< self.param.k {
            var AUTH: Bytes = []
            SIGfors += forsSKgen(SKseed, PKseed, adrs, i << self.param.a + indices[i])
            for j in 0 ..< self.param.a {
                let s = (indices[i] >> j) ^ 1
                AUTH += forsNode(SKseed, i << (self.param.a - j) + s, j, PKseed, adrs)
            }
            SIGfors += AUTH
        }
        return SIGfors
    }
    
    // [FIPS 205] - Algorithm 16
    func forsPKFromSig(_ SIGfors: Bytes, _ md: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes{
        assert(PKseed.count == self.param.n)
        assert(SIGfors.count == self.param.k * self.param.n * (self.param.a + 1))
        var adrs = adrs
        let indices = base2b(md, self.param.a, self.param.k)
        var root: Bytes = []
        var node0: Bytes
        var node1: Bytes = []
        var SIGforsSlice = SIGfors.sliced()
        for i in 0 ..< self.param.k {
            adrs.setTreeHeight(0)
            adrs.setTreeIndex(i << self.param.a + indices[i])
            node0 = F(PKseed, adrs, SIGforsSlice.next(self.param.n))
            for j in 0 ..< self.param.a {
                adrs.setTreeHeight(j + 1)
                if (indices[i] >> j) & 1 == 0 {
                    adrs.setTreeIndex(adrs.getTreeIndex() >> 1)
                    node1 = H(PKseed, adrs, node0 + SIGforsSlice.next(self.param.n))
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1)
                    node1 = H(PKseed, adrs, SIGforsSlice.next(self.param.n) + node0)
                }
                node0 = node1
            }
            root += node0
        }
        var forspkAdrs = adrs
        forspkAdrs.setType(ADRS.FORS_ROOTS)
        forspkAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
        let pk = T(PKseed, forspkAdrs,root)
        return pk
    }
    
    // [FIPS 205] - Algorithm 17
    func slhKeyGen(_ seed: Bytes = []) -> (sk: Bytes, pk: Bytes) {
        assert(seed.count == 0 || seed.count == self.param.n * 3)
        var rnd = Bytes(repeating: 0, count: self.param.n * 3)
        if seed.count == 0 {
            SPHINCS.randomBytes(&rnd)
        } else {
            rnd = seed
        }
        var rndSlice = rnd.sliced()
        let SKseed = rndSlice.next(self.param.n)
        let SKprf = rndSlice.next(self.param.n)
        let PKseed = rndSlice.next(self.param.n)
        var adrs = ADRS()
        adrs.setLayerAddress(self.param.d - 1)
        let PKroot = xmssNode(SKseed, 0, self.param.h1, PKseed, adrs)
        return (SKseed + SKprf + PKseed + PKroot, PKseed + PKroot)
    }
    
    // [FIPS 205] - Algorithm 18
    func slhSign(_ M: Bytes, _ SK: Bytes, _ randomize: Bool = true) -> Bytes {
        var adrs = ADRS()
        var SKSlice = SK.sliced()
        let SKseed = SKSlice.next(self.param.n)
        let SKprf = SKSlice.next(self.param.n)
        let PKseed = SKSlice.next(self.param.n)
        let PKroot = SKSlice.next(self.param.n)
        var optRand: Bytes
        if randomize {
            optRand = Bytes(repeating: 0, count: PKseed.count)
            SPHINCS.randomBytes(&optRand)
        } else {
            optRand = PKseed
        }
        let R = PRFmsg(SKprf, optRand, M)
        var SIG = R
        let digest = Hmsg(R, PKseed, PKroot, M)
        var digestSlice = digest.sliced()
        let md = digestSlice.next(self.param.mdSize)
        let idxTree = toInt(digestSlice.next(self.param.treeSize), self.param.treeSize) & self.param.treeMask
        let idxLeaf = toInt(digestSlice.next(self.param.leafSize), self.param.leafSize) & self.param.leafMask
        adrs.setTreeAddress(idxTree)
        adrs.setType(ADRS.FORS_TREE)
        adrs.setKeyPairAddress(idxLeaf)
        let SIGfors = forsSign(md, SKseed, PKseed, adrs)
        SIG += SIGfors
        let PKfors = forsPKFromSig(SIGfors, md, PKseed, adrs)
        let SIGht = htSign(PKfors, SKseed, PKseed, idxTree, idxLeaf)
        SIG += SIGht
        return SIG
    }
    
    // [FIPS 205] - Algorithm 19
    func slhVerify(_ M: Bytes, _ SIG: Bytes, _ PK: Bytes) -> Bool {
        if SIG.count != self.param.n * (1 + self.param.k * (1 + self.param.a) + self.param.h + self.param.d * self.param.len) {
            return false
        }
        var PKSlice = PK.sliced()
        let PKseed = PKSlice.next(self.param.n)
        let PKroot = PKSlice.next(self.param.n)
        var adrs = ADRS()
        var SIGSlice = SIG.sliced()
        
        let R = SIGSlice.next(self.param.n)
        let SIGfors = SIGSlice.next(self.param.n * self.param.k * (1 + self.param.a))
        let SIGht = SIGSlice.next(self.param.n * (self.param.h + self.param.len * self.param.d))
        let digest = Hmsg(R, PKseed, PKroot, M)
        var digestSlice = digest.sliced()
        let md = digestSlice.next(self.param.mdSize)
        let idxTree = toInt(digestSlice.next(self.param.treeSize), self.param.treeSize) & self.param.treeMask
        let idxLeaf = toInt(digestSlice.next(self.param.leafSize), self.param.leafSize) & self.param.leafMask
        adrs.setTreeAddress(idxTree)
        adrs.setType(ADRS.FORS_TREE)
        adrs.setKeyPairAddress(idxLeaf)
        let PKfors = forsPKFromSig(SIGfors, md, PKseed, adrs)
        return htVerify(PKfors, SIGht, PKseed, idxTree, idxLeaf, PKroot)
    }
    
}
