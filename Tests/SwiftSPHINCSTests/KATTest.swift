//
//  Test128.swift
//  
//
//  Created by Leif Ibsen on 21/12/2023.
//

import XCTest
@testable import SwiftSPHINCS
import Digest

final class KATTest: XCTestCase {

    // Test vectors from the GitHub Python project 'slh-dsa-py'

    struct katTest {
        let kind: SPHINCSKind
        let seed: Bytes
        let msg: Bytes
        let pk: Bytes
        let sk: Bytes
        let digest: Bytes
        
        init(kind: SPHINCSKind, seed: String, msg: String, pk: String, sk: String, digest: String) {
            self.kind = kind
            self.seed = Util.hex2bytes(seed)
            self.msg = Util.hex2bytes(msg)
            self.pk = Util.hex2bytes(pk)
            self.sk = Util.hex2bytes(sk)
            self.digest = Util.hex2bytes(digest)
        }
    }

    var katTests: [katTest] = [
        katTest(
            kind: SPHINCSKind.SHA2_128f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "b505d7cfad1b497499323c8686325e47fdf7400ab7a5d8c7aba7350ac4092add",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47fdf7400ab7a5d8c7aba7350ac4092add",
            digest: "d5fcac774c8e0beb1972cbca07acaa8469cae7f71b95cc06f61d6c49b99eb133"),
        katTest(
            kind: SPHINCSKind.SHA2_128s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "b505d7cfad1b497499323c8686325e476d2e5993d919b7f288cc823133046cf9",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e476d2e5993d919b7f288cc823133046cf9",
            digest: "c94c0b787890671f878264749b6a782a4504d39186590f56d27e53d356af7e67"),
        katTest(
            kind: SPHINCSKind.SHA2_192f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "92f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfdad7ef867981e22877aa4c2a8829f657e931c55409b897d2e",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfdad7ef867981e22877aa4c2a8829f657e931c55409b897d2e",
            digest: "1b6ccd17e537107e45367c217c3c4fe34acd1b7321601ec29307d90bd6846539"),
        katTest(
            kind: SPHINCSKind.SHA2_192s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "92f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfdee27692ef30bad87b55c4e2a25e7f47875c1f53723ce31c6",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfdee27692ef30bad87b55c4e2a25e7f47875c1f53723ce31c6",
            digest: "a4d9a15d1e602dbf67f4922f21f0c3ba1ba6b3ace12c3050df8103632bc8d62e"),
        katTest(
            kind: SPHINCSKind.SHA2_256f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aad9d73f07f69a7d12c49b9a367de0668544e8471660678a4ef7cee8be9638ca53",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aad9d73f07f69a7d12c49b9a367de0668544e8471660678a4ef7cee8be9638ca53",
            digest: "6aae4167de548a3f2498e321de2717a6074f9971cd96d56250540d94e658f200"),
        katTest(
            kind: SPHINCSKind.SHA2_256s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa026f566cdcd2987eb7ab1ec71e86b617f97b98ef63902e283fb5249119c6ceb0",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa026f566cdcd2987eb7ab1ec71e86b617f97b98ef63902e283fb5249119c6ceb0",
            digest: "ddcbcce263bd9170eba3634c3492bff42a43f2e7a4ffff0899943c6ca9260d10"),
        katTest(
            kind: SPHINCSKind.SHAKE_128f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "b505d7cfad1b497499323c8686325e47afbc007ba1e2b4a138f03aa9a6195ac8",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47afbc007ba1e2b4a138f03aa9a6195ac8",
            digest: "8ed1eb2ee342f0d8b192bf887cbf913036f4e4d9b20970fdcce1dd94c5cb51aa"),
        katTest(
            kind: SPHINCSKind.SHAKE_128s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "b505d7cfad1b497499323c8686325e47ac524902fc81f5032bc27b17d9261ebd",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e47ac524902fc81f5032bc27b17d9261ebd",
            digest: "4f294d3f01f444fee905846f4d6102451f61be02a173a39c4280471db524dacb"),
        katTest(
            kind: SPHINCSKind.SHAKE_192f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "92f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd9b836b00b9f458c1a193f062a9a3cdafe7869f47546cb346",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd9b836b00b9f458c1a193f062a9a3cdafe7869f47546cb346",
            digest: "fa20dbfa2ae229cdc9a32c56262e9dd795203dd675ba4f7e2fec385c0348d175"),
        katTest(
            kind: SPHINCSKind.SHAKE_192s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "92f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd0bde2780ed4ccdaf544d88f22d41610d4ef994825cfb4d45",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd0bde2780ed4ccdaf544d88f22d41610d4ef994825cfb4d45",
            digest: "a96de5862c94fafc003fd3745279758ca83f4ead32ec62b735d4f6b5ac4c1533"),
        katTest(
            kind: SPHINCSKind.SHAKE_256f,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa514264d1b7ef27574ae6933e374225cf87683de3bfee657200f3667c8d800722",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa514264d1b7ef27574ae6933e374225cf87683de3bfee657200f3667c8d800722",
            digest: "09828b9b621b8cbaad99e15dff5e2598c70c7863d0203112c77e56cf70b4981a"),
        katTest(
            kind: SPHINCSKind.SHAKE_256s,
            seed: "061550234d158c5ec95595fe04ef7a25767f2e24cc2bc479d09d86dc9abcfde7056a8c266f9ef97ed08541dbd2e1ffa1",
            msg: "d81c4d8d734fcbfbeade3d3f8a039faa2a2c9957e835ad55b22e75bf57bb556ac8",
            pk: "3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa3623940d5d834494148a661f9ac6a96bdc54ad4d0b8b0913484a9233c56212a4",
            sk: "7c9935a0b07694aa0c6d10e4db6b1add2fd81a25ccb148032dcd739936737f2db505d7cfad1b497499323c8686325e4792f267aafa3f87ca60d01cb54f29202a3e784ccb7ebcdcfd45542b7f6af778742e0f4479175084aa488b3b74340678aa3623940d5d834494148a661f9ac6a96bdc54ad4d0b8b0913484a9233c56212a4",
            digest: "88f6b16a981f959e052c301c2c766322500b0f43d18449f16687b7a388b641eb"),

    ]

    func test() {
        for t in katTests {
            let sphincs = SPHINCS(kind: t.kind)
            let rnd = DRBG(t.seed).randomBytes(3 * sphincs.param.n)
            let md = MessageDigest(.SHA2_256)
            let (skKey, pkKey) = sphincs.slhKeyGen(rnd)
            XCTAssertEqual(skKey, t.sk)
            XCTAssertEqual(pkKey, t.pk)
            let sig = sphincs.slhSign(t.msg, skKey, false)
            md.update(sig)
            md.update(t.msg)
            XCTAssertEqual(md.digest(), t.digest)
            XCTAssertTrue(sphincs.slhVerify(t.msg, sig, pkKey))
        }
    }

}
