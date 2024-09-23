//
//  File.swift
//  
//
//  Created by Leif Ibsen on 12/12/2023.
//

/// The SPHINCS exceptions
public enum Exception: Error {

    /// Wrong ASN1 structure
    case asn1Structure
    
    /// Wrong context size
    case contextSize(value: Int)

    /// Invalid secret key bytes
    case invalidSecretKey

    /// Wrong PEM structure
    case pemStructure

    /// Wrong public key size
    case publicKeySize(value: Int)

    /// Wrong secret key size
    case secretKeySize(value: Int)

}
