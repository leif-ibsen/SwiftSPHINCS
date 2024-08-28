//
//  Kind.swift
//  
//
//  Created by Leif Ibsen on 01/02/2024.
//

/// The SPHINCS parameter sets
public enum SPHINCSKind: CaseIterable {
    /// SLH-DSA-SHA2-128s
    case SHA2_128s
    /// SLH-DSA-SHAKE-128s
    case SHAKE_128s
    /// SLH-DSA-SHA2-128f
    case SHA2_128f
    /// SLH-DSA-SHAKE-128f
    case SHAKE_128f
    /// SLH-DSA-SHA2-192s
    case SHA2_192s
    /// SLH-DSA-SHAKE-192s
    case SHAKE_192s
    /// SLH-DSA-SHA2-192f
    case SHA2_192f
    /// SLH-DSA-SHAKE-192f
    case SHAKE_192f
    /// SLH-DSA-SHA2-256s
    case SHA2_256s
    /// SLH-DSA-SHAKE-256s
    case SHAKE_256s
    /// SLH-DSA-SHA2-256f
    case SHA2_256f
    /// SLH-DSA-SHAKE-256f
    case SHAKE_256f
}
