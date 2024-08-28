//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

/// The SPHINCS exceptions
public enum SPHINCSException: Error {

    /// Invalid secret key bytes
    case invalidSecretKey

    /// Wrong secret key size
    case secretKeySize

    /// Wrong public key size
    case publicKeySize

    /// Wrong context size
    case contextSize

}
