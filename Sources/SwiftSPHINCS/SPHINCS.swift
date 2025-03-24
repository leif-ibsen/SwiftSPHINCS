//
//  SPHINCS.swift
//  Slice
//
//  Created by Leif Ibsen on 10/12/2023.
//

import Foundation
import ASN1
import Digest

/// Unsigned 8 bit value
public typealias Byte = UInt8

/// Array of unsigned 8 bit values
public typealias Bytes = [UInt8]

typealias Word = UInt32
typealias Words = [UInt32]

public struct SPHINCS {
    
    static func randomBytes(_ n: Int) -> Bytes {
        var bytes = Bytes(repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &bytes) == errSecSuccess else {
            fatalError("SecRandomCopyBytes failed")
        }
        return bytes
    }

    let kind: Kind
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
    let keySize: Int
    let oid: ASN1ObjectIdentifier
    let shake128: SHAKE
    let shake256: SHAKE
    let sha256: MessageDigest
    let sha512: MessageDigest
    
    // MARK: Initializer

    init(_ kind: Kind) {
        let param = Parameters.paramsFromKind(kind)
        self.kind = kind
        self.n = param.n
        self.h = param.h
        self.d = param.d
        self.h1 = param.h1
        self.a = param.a
        self.k = param.k
        self.lgw = param.lgw
        self.m = param.m
        self.mdSize = param.mdSize
        self.treeSize = param.treeSize
        self.leafSize = param.leafSize
        self.treeMask = param.treeMask
        self.leafMask = param.leafMask
        self.w = param.w
        self.len = param.len
        self.len1 = param.len1
        self.len2 = param.len2
        self.keySize = param.keySize
        self.oid = param.oid
        self.shake128 = SHAKE(.SHAKE128)
        self.shake256 = SHAKE(.SHAKE256)
        self.sha256 = MessageDigest(.SHA2_256)
        self.sha512 = MessageDigest(.SHA2_512)
    }
    
    
    // MARK: Methods
    
    /// Generates a secret key and a public key of a specified kind
    ///
    /// - Parameters:
    ///   - kind: The SPHINCS kind
    /// - Returns: The secret key `sk` and the public key `pk`
    public static func GenerateKeyPair(kind: Kind) -> (sk: SecretKey, pk: PublicKey) {
        let sphincs = SPHINCS(kind)
        let (sk, _) = sphincs.slhKeyGen()
        do {
            let secretKey = try SecretKey(sphincs, sk)
            return (secretKey, secretKey.publicKey)
        } catch {
            // Shouldn't happen
            fatalError("GenerateKeyPair inconsistency")
        }
    }
    
    func Trunc(_ x: Bytes) -> Bytes {
        return Bytes(x[0 ..< self.n])
    }
    
    func Hmsg(_ R: Bytes, _ PKseed: Bytes, _ PKroot: Bytes, _ M: Bytes) -> Bytes {
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(R)
            self.shake256.update(PKseed)
            self.shake256.update(PKroot)
            self.shake256.update(M)
            return self.shake256.digest(self.m)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(R)
            self.sha256.update(PKseed)
            self.sha256.update(PKroot)
            self.sha256.update(M)
            return KDF.MGF1(.SHA2_256, R + PKseed + self.sha256.digest(), self.m)
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(R)
            self.sha512.update(PKseed)
            self.sha512.update(PKroot)
            self.sha512.update(M)
            return KDF.MGF1(.SHA2_512, R + PKseed + self.sha512.digest(), self.m)
        }
    }
    
    func PRF(_ PKseed: Bytes, _ SKseed: Bytes, _ adrs: ADRS) -> Bytes {
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(SKseed)
            return self.shake256.digest(self.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(SKseed)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
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
            return self.shake256.digest(self.n)
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
        assert(M1.count == self.n)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M1)
            return self.shake256.digest(self.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M1)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M1)
            return Trunc(self.sha256.digest())
        }
    }

    func H(_ PKseed: Bytes, _ adrs: ADRS, _ M2: Bytes) -> Bytes {
        assert(M2.count == self.n << 1)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M2)
            return self.shake256.digest(self.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M2)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(PKseed)
            self.sha512.update(toByte(0, 128 - self.n))
            self.sha512.update(adrs.compress())
            self.sha512.update(M2)
            return Trunc(self.sha512.digest())
        }
    }
    
    func T(_ PKseed: Bytes, _ adrs: ADRS, _ M: Bytes) -> Bytes {
        assert(M.count % self.n == 0)
        switch self.kind {
        case .SHAKE_128s, .SHAKE_128f, .SHAKE_192s, .SHAKE_192f, .SHAKE_256s, .SHAKE_256f:
            self.shake256.update(PKseed)
            self.shake256.update(adrs.bytes)
            self.shake256.update(M)
            return self.shake256.digest(self.n)
        case .SHA2_128s, .SHA2_128f:
            self.sha256.update(PKseed)
            self.sha256.update(toByte(0, 64 - self.n))
            self.sha256.update(adrs.compress())
            self.sha256.update(M)
            return Trunc(self.sha256.digest())
        case .SHA2_192s, .SHA2_192f, .SHA2_256s, .SHA2_256f:
            self.sha512.update(PKseed)
            self.sha512.update(toByte(0, 128 - self.n))
            self.sha512.update(adrs.compress())
            self.sha512.update(M)
            return Trunc(self.sha512.digest())
        }
    }
    
    // [FIPS 205] - Algorithm 2
    func toInt(_ X: Bytes, _ n: Int) -> Int {
        assert(X.count == n)
        var total = 0
        for i in 0 ..< n {
            total = total << 8 | Int(X[i])
        }
        return total
    }
    
    // [FIPS 205] - Algorithm 3
    func toByte(_ x: Int, _ n: Int) -> Bytes {
        var S = Bytes(repeating: 0, count: n)
        var total = x
        for i in 0 ..< n {
            S[n - 1 - i] = Byte(total & 0xff)
            total >>= 8
        }
        return S
    }
    
    // [FIPS 205] - Algorithm 4
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
    
    // [FIPS 205] - Algorithm 5
    func chain(_ X: Bytes, _ i: Int , _ s: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(PKseed.count == self.n)
        assert(i + s < self.w)
        var adrs = adrs
        var tmp = X
        for j in i ..< i + s {
            adrs.setHashAddress(j)
            tmp = F(PKseed, adrs, tmp)
        }
        return tmp
    }
    
    // [FIPS 205] - Algorithm 6
    func wotsPKgen(_ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var skADRS = adrs
        skADRS.setTypeAndClear(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        var tmp: Bytes = []
        for i in 0 ..< self.len {
            skADRS.setChainAddress(i)
            let sk = PRF(PKseed, SKseed, skADRS)
            adrs.setChainAddress(i)
            tmp += chain(sk, 0, self.w - 1, PKseed, adrs)
        }
        var wotspkADRS = adrs
        wotspkADRS.setTypeAndClear(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        return T(PKseed, wotspkADRS, tmp)
    }
    
    // [FIPS 205] - Algorithm 7
    func wotsSign(_ M: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(M.count == self.n)
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var csum = 0
        var sig: Bytes = []
        var msg = base2b(M, self.lgw, self.len1)
        for i in 0 ..< self.len1 {
            csum += self.w - 1 - msg[i]
        }
        csum <<= 4
        msg += base2b(toByte(csum, 2), self.lgw, self.len2)
        var skADRS = adrs
        skADRS.setTypeAndClear(ADRS.WOTS_PRF)
        skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        for i in 0 ..< self.len {
            skADRS.setChainAddress(i)
            let sk = PRF(PKseed, SKseed, skADRS)
            adrs.setChainAddress(i)
            sig += chain(sk, 0, msg[i], PKseed, adrs)
        }
        assert(sig.count == self.n * self.len)
        return sig
    }
    
    // [FIPS 205] - Algorithm 8
    func wotsPKFromSig(_ sig: Bytes, _ M: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(sig.count == self.n * self.len)
        assert(M.count == self.n)
        assert(PKseed.count == self.n)
        assert(adrs.getType() == ADRS.WOTS_HASH)
        var adrs = adrs
        var csum = 0
        var msg = base2b(M, self.lgw, self.len1)
        for i in 0 ..< self.len1 {
            csum += self.w - 1 - msg[i]
        }
        csum <<= 4
        msg += base2b(toByte(csum, 2), self.lgw, self.len2)
        var tmp: Bytes = []
        var sigSlice = sig.sliced()
        for i in 0 ..< self.len {
            adrs.setChainAddress(i)
            tmp += chain(sigSlice.next(self.n), msg[i], self.w - 1 - msg[i], PKseed, adrs)
        }
        var wotspkADRS = adrs
        wotspkADRS.setTypeAndClear(ADRS.WOTS_PK)
        wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
        return T(PKseed, wotspkADRS, tmp)
    }

    // [FIPS 205] - Algorithm 9
    func xmssNode(_ SKseed: Bytes, _ i: Int, _ z: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        assert(z <= self.h1)
        assert(i < 1 << (self.h1 - z))
        var adrs = adrs
        if z == 0 {
            adrs.setTypeAndClear(ADRS.WOTS_HASH)
            adrs.setKeyPairAddress(i)
            return wotsPKgen(SKseed, PKseed, adrs)
        } else {
            let lnode = xmssNode(SKseed, i << 1, z - 1, PKseed, adrs)
            let rnode = xmssNode(SKseed, i << 1 + 1, z - 1, PKseed, adrs)
            adrs.setTypeAndClear(ADRS.TREE)
            adrs.setTreeHeight(z)
            adrs.setTreeIndex(i)
            return H(PKseed, adrs, lnode + rnode)
        }
    }
    
    // [FIPS 205] - Algorithm 10
    func xmssSign(_ M: Bytes, _ SKseed: Bytes, _ idx: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(M.count == self.n)
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        assert(idx >= 0)
        var adrs = adrs
        var AUTH: Bytes = []
        for j in 0 ..< self.h1 {
            let k = (idx >> j) ^ 1
            AUTH += xmssNode(SKseed, k, j, PKseed, adrs)
        }
        adrs.setTypeAndClear(ADRS.WOTS_HASH)
        adrs.setKeyPairAddress(idx)
        let sig = wotsSign(M, SKseed, PKseed, adrs)
        let SIGxmss = sig + AUTH
        assert(SIGxmss.count == self.n * (self.len + self.h1))
        return SIGxmss
    }

    // [FIPS 205] - Algorithm 11
    func xmssPKFromSig(_ idx: Int, _ SIGxmss: Bytes, _ M: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SIGxmss.count == (self.len + self.h1) * self.n)
        assert(M.count == self.n)
        assert(PKseed.count == self.n)
        var adrs = adrs
        adrs.setTypeAndClear(ADRS.WOTS_HASH)
        adrs.setKeyPairAddress(idx)
        var SIGxmssSlice = SIGxmss.sliced()
        
        let sig = SIGxmssSlice.next(self.len * self.n)
        var node0 = wotsPKFromSig(sig, M, PKseed, adrs)
        var node1: Bytes
        adrs.setTypeAndClear(ADRS.TREE)
        adrs.setTreeIndex(idx)
        for k in 0 ..< self.h1 {
            adrs.setTreeHeight(k + 1)
            if (idx >> k) & 1 == 0 {
                adrs.setTreeIndex(adrs.getTreeIndex() >> 1)
                node1 = H(PKseed, adrs, node0 + SIGxmssSlice.next(self.n))
            } else {
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1)
                node1 = H(PKseed, adrs, SIGxmssSlice.next(self.n) + node0)
            }
            node0 = node1
        }
        return node0
    }
    
    // [FIPS 205] - Algorithm 12
    func htSign(_ M: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ idxTree: Int, _ idxLeaf: Int) -> Bytes {
        assert(M.count == self.n)
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        var idxTree = idxTree
        var idxLeaf = idxLeaf
        var adrs = ADRS()
        adrs.setTreeAddress(idxTree)
        var SIGtmp = xmssSign(M, SKseed, idxLeaf, PKseed, adrs)
        var SIGht = SIGtmp
        var root = xmssPKFromSig(idxLeaf, SIGtmp, M, PKseed, adrs)
        let mask1 = 1 << self.h1 - 1
        let mask2 = 1 << (64 - self.h1) - 1
        for j in 1 ..< self.d {
            idxLeaf = idxTree & mask1
            idxTree = (idxTree >> self.h1) & mask2
            adrs.setLayerAddress(j)
            adrs.setTreeAddress(idxTree)
            SIGtmp = xmssSign(root, SKseed, idxLeaf, PKseed, adrs)
            SIGht += SIGtmp
            if j < self.d - 1 {
                root = xmssPKFromSig(idxLeaf, SIGtmp, root, PKseed, adrs)
            }
        }
        return SIGht
    }
    
    // [FIPS 205] - Algorithm 13
    func htVerify(_ M: Bytes, _ SIGht: Bytes, _ PKseed: Bytes, _ idxTree: Int, _ idxLeaf: Int, _ PKroot: Bytes) -> Bool {
        assert(M.count == self.n)
        assert(SIGht.count == (self.h + self.d * self.len) * self.n)
        assert(PKseed.count == self.n)
        assert(PKroot.count == self.n)
        var idxTree = idxTree
        var idxLeaf = idxLeaf
        var adrs = ADRS()
        adrs.setTreeAddress(idxTree)
        var SIGhtSlice = SIGht.sliced()
        let l = (self.h1 + self.len) * self.n
        var node = xmssPKFromSig(idxLeaf, SIGhtSlice.next(l), M, PKseed, adrs)
        let mask1 = (1 << self.h1 - 1)
        let mask2 = (1 << (64 - self.h1) - 1)
        for j in 1 ..< self.d {
            idxLeaf = idxTree & mask1
            idxTree = (idxTree >> self.h1) & mask2
            adrs.setLayerAddress(j)
            adrs.setTreeAddress(idxTree)
            node = xmssPKFromSig(idxLeaf, SIGhtSlice.next(l), node, PKseed, adrs)
        }
        return node == PKroot
    }
    
    // [FIPS 205] - Algorithm 14
    func forsSKgen(_ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS, _ idx: Int) -> Bytes {
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        var skAdrs = adrs
        skAdrs.setTypeAndClear(ADRS.FORS_PRF)
        skAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
        skAdrs.setTreeIndex(idx)
        return PRF(PKseed, SKseed, skAdrs)
    }
    
    // [FIPS 205] - Algorithm 15
    func forsNode(_ SKseed: Bytes, _ i: Int, _ z: Int, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        var adrs = adrs
        if z > self.a || i >= self.k * (1 << (self.a - z)) {
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
    
    // [FIPS 205] - Algorithm 16
    func forsSign(_ md: Bytes, _ SKseed: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes {
        assert(SKseed.count == self.n)
        assert(PKseed.count == self.n)
        var SIGfors: Bytes = []
        let indices = base2b(md, self.a, self.k)
        for i in 0 ..< self.k {
            var AUTH: Bytes = []
            SIGfors += forsSKgen(SKseed, PKseed, adrs, i << self.a + indices[i])
            for j in 0 ..< self.a {
                let s = (indices[i] >> j) ^ 1
                AUTH += forsNode(SKseed, i << (self.a - j) + s, j, PKseed, adrs)
            }
            SIGfors += AUTH
        }
        return SIGfors
    }
    
    // [FIPS 205] - Algorithm 17
    func forsPKFromSig(_ SIGfors: Bytes, _ md: Bytes, _ PKseed: Bytes, _ adrs: ADRS) -> Bytes{
        assert(PKseed.count == self.n)
        assert(SIGfors.count == self.k * self.n * (self.a + 1))
        var adrs = adrs
        let indices = base2b(md, self.a, self.k)
        var root: Bytes = []
        var node0: Bytes
        var node1: Bytes = []
        var SIGforsSlice = SIGfors.sliced()
        for i in 0 ..< self.k {
            adrs.setTreeHeight(0)
            adrs.setTreeIndex(i << self.a + indices[i])
            node0 = F(PKseed, adrs, SIGforsSlice.next(self.n))
            for j in 0 ..< self.a {
                adrs.setTreeHeight(j + 1)
                if (indices[i] >> j) & 1 == 0 {
                    adrs.setTreeIndex(adrs.getTreeIndex() >> 1)
                    node1 = H(PKseed, adrs, node0 + SIGforsSlice.next(self.n))
                } else {
                    adrs.setTreeIndex((adrs.getTreeIndex() - 1) >> 1)
                    node1 = H(PKseed, adrs, SIGforsSlice.next(self.n) + node0)
                }
                node0 = node1
            }
            root += node0
        }
        var forspkAdrs = adrs
        forspkAdrs.setTypeAndClear(ADRS.FORS_ROOTS)
        forspkAdrs.setKeyPairAddress(adrs.getKeyPairAddress())
        return T(PKseed, forspkAdrs, root)
    }
    
    // [FIPS] - Algorithm 18
    func slhKeyGenInternal(_ SKseed: Bytes, _ SKprf: Bytes, _ PKseed: Bytes) -> (sk: Bytes, pk: Bytes) {
        assert(SKseed.count == self.n)
        assert(SKprf.count == self.n)
        assert(PKseed.count == self.n)
        var adrs = ADRS()
        adrs.setLayerAddress(self.d - 1)
        let PKroot = xmssNode(SKseed, 0, self.h1, PKseed, adrs)
        return (SKseed + SKprf + PKseed + PKroot, PKseed + PKroot)
    }

    // [FIPS] - Algorithm 19
    func slhSignInternal(_ M: Bytes, _ SK: Bytes, _ randomize: Bool) -> Bytes {
        var adrs = ADRS()
        var SKSlice = SK.sliced()
        let SKseed = SKSlice.next(self.n)
        let SKprf = SKSlice.next(self.n)
        let PKseed = SKSlice.next(self.n)
        let PKroot = SKSlice.next(self.n)
        let optRand = randomize ? SPHINCS.randomBytes(PKseed.count) : PKseed
        let R = PRFmsg(SKprf, optRand, M)
        var SIG = R
        let digest = Hmsg(R, PKseed, PKroot, M)
        var digestSlice = digest.sliced()
        let md = digestSlice.next(self.mdSize)
        let idxTree = toInt(digestSlice.next(self.treeSize), self.treeSize) & self.treeMask
        let idxLeaf = toInt(digestSlice.next(self.leafSize), self.leafSize) & self.leafMask
        adrs.setTreeAddress(idxTree)
        adrs.setTypeAndClear(ADRS.FORS_TREE)
        adrs.setKeyPairAddress(idxLeaf)
        let SIGfors = forsSign(md, SKseed, PKseed, adrs)
        SIG += SIGfors
        let PKfors = forsPKFromSig(SIGfors, md, PKseed, adrs)
        let SIGht = htSign(PKfors, SKseed, PKseed, idxTree, idxLeaf)
        SIG += SIGht
        return SIG
    }

    // [FIPS] - Algorithm 20
    func slhVerifyInternal(_ M: Bytes, _ SIG: Bytes, _ PK: Bytes) -> Bool {
        if SIG.count != self.n * (1 + self.k * (1 + self.a) + self.h + self.d * self.len) {
            return false
        }
        var PKSlice = PK.sliced()
        let PKseed = PKSlice.next(self.n)
        let PKroot = PKSlice.next(self.n)
        var adrs = ADRS()
        var SIGSlice = SIG.sliced()
        let R = SIGSlice.next(self.n)
        let SIGfors = SIGSlice.next(self.n * self.k * (1 + self.a))
        let SIGht = SIGSlice.next(self.n * (self.h + self.len * self.d))
        let digest = Hmsg(R, PKseed, PKroot, M)
        var digestSlice = digest.sliced()
        let md = digestSlice.next(self.mdSize)
        let idxTree = toInt(digestSlice.next(self.treeSize), self.treeSize) & self.treeMask
        let idxLeaf = toInt(digestSlice.next(self.leafSize), self.leafSize) & self.leafMask
        adrs.setTreeAddress(idxTree)
        adrs.setTypeAndClear(ADRS.FORS_TREE)
        adrs.setKeyPairAddress(idxLeaf)
        let PKfors = forsPKFromSig(SIGfors, md, PKseed, adrs)
        return htVerify(PKfors, SIGht, PKseed, idxTree, idxLeaf, PKroot)
    }
    
    // [FIPS 205] - Algorithm 21
    func slhKeyGen() -> (sk: Bytes, pk: Bytes) {
        let SKseed = SPHINCS.randomBytes(self.n)
        let SKprf = SPHINCS.randomBytes(self.n)
        let PKseed = SPHINCS.randomBytes(self.n)
        return slhKeyGenInternal(SKseed, SKprf, PKseed)
    }
    
    // [FIPS 205] - Algorithm 22
    func slhSign(_ M: Bytes, _ ctx: Bytes, _ SK: Bytes, _ randomize: Bool) -> Bytes {
        assert(ctx.count < 256)
        let M1 = [0] + [Byte(ctx.count)] + ctx + M
        return slhSignInternal(M1, SK, randomize)
    }
    
    // [FIPS 205] - Algorithm 23
    func hashSlhSign(_ M: Bytes, _ ctx: Bytes, _ PH: PreHash, _ SK: Bytes, _ randomize: Bool) -> Bytes {
        assert(ctx.count < 256)
        var OID: Bytes
        var phM: Bytes
        switch PH {
        case .SHA2_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4]
            phM = MessageDigest(.SHA2_224).digest(M)
        case .SHA2_256, .SHA256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1]
            phM = MessageDigest(.SHA2_256).digest(M)
        case .SHA2_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2]
            phM = MessageDigest(.SHA2_384).digest(M)
        case .SHA2_512, .SHA512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3]
            phM = MessageDigest(.SHA2_512).digest(M)
        case .SHA3_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 7]
            phM = MessageDigest(.SHA3_224).digest(M)
        case .SHA3_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 8]
            phM = MessageDigest(.SHA3_256).digest(M)
        case .SHA3_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 9]
            phM = MessageDigest(.SHA3_384).digest(M)
        case .SHA3_512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10]
            phM = MessageDigest(.SHA3_512).digest(M)
        case .SHAKE128:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 11]
            phM = XOF(.XOF128, M).read(32)
        case .SHAKE256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 12]
            phM = XOF(.XOF256, M).read(64)
        }
        let M1 = [1] + [Byte(ctx.count)] + ctx + OID + phM
        return slhSignInternal(M1, SK, randomize)
    }
    
    // [FIPS 205] - Algorithm 24
    func slhVerify(_ M: Bytes, _ SIG: Bytes, _ ctx: Bytes, _ PK: Bytes) -> Bool {
        if ctx.count > 255 {
            return false
        }
        let M1 = [0] + [Byte(ctx.count)] + ctx + M
        return slhVerifyInternal(M1, SIG, PK)
    }
    
    // [FIPS 205] - Algorithm 25
    func hashSlhVerify(_ M: Bytes, _ SIG: Bytes, _ ctx: Bytes, _ PH: PreHash, _ PK: Bytes) -> Bool {
        if ctx.count > 255 {
            return false
        }
        var OID: Bytes
        var phM: Bytes
        switch PH {
        case .SHA2_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 4]
            phM = MessageDigest(.SHA2_224).digest(M)
        case .SHA2_256, .SHA256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1]
            phM = MessageDigest(.SHA2_256).digest(M)
        case .SHA2_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 2]
            phM = MessageDigest(.SHA2_384).digest(M)
        case .SHA2_512, .SHA512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 3]
            phM = MessageDigest(.SHA2_512).digest(M)
        case .SHA3_224:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 7]
            phM = MessageDigest(.SHA3_224).digest(M)
        case .SHA3_256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 8]
            phM = MessageDigest(.SHA3_256).digest(M)
        case .SHA3_384:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 9]
            phM = MessageDigest(.SHA3_384).digest(M)
        case .SHA3_512:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 10]
            phM = MessageDigest(.SHA3_512).digest(M)
        case .SHAKE128:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 11]
            phM = XOF(.XOF128, M).read(32)
        case .SHAKE256:
            OID = [6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 12]
            phM = XOF(.XOF256, M).read(64)
        }
        let M1 = [1] + [Byte(ctx.count)] + ctx + OID + phM
        return slhVerifyInternal(M1, SIG, PK)
    }
    
}
