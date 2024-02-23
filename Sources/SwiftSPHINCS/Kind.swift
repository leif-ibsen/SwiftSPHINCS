//
//  Kind.swift
//  
//
//  Created by Leif Ibsen on 01/02/2024.
//

/// The SPHINCS parameter sets
public enum SPHINCSKind: CaseIterable {
    /// SLH-DSA-SHA2-128s kind
    case SHA2_128s
    /// SLH-DSA-SHAKE-128s kind
    case SHAKE_128s
    /// SLH-DSA-SHA2-128f kind
    case SHA2_128f
    /// SLH-DSA-SHAKE-128f kind
    case SHAKE_128f
    /// SLH-DSA-SHA2-192s kind
    case SHA2_192s
    /// SLH-DSA-SHAKE-192s kind
    case SHAKE_192s
    /// SLH-DSA-SHA2-192f kind
    case SHA2_192f
    /// SLH-DSA-SHAKE-192f kind
    case SHAKE_192f
    /// SLH-DSA-SHA2-256s kind
    case SHA2_256s
    /// SLH-DSA-SHAKE-256s kind
    case SHAKE_256s
    /// SLH-DSA-SHA2-256f kind
    case SHA2_256f
    /// SLH-DSA-SHAKE-256f kind
    case SHAKE_256f
}
