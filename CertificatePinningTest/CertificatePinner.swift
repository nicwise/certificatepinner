//
// CertificatePinner - (C) Nic Wise and others, 2016
//
// https://github.com/nicwise/certificatepinner
//
// License: MIT.
//


import Foundation
import Security

/*
In order to use this, you need to pull this file in, as well as CertificatePinner_swiftBridge.h

If you already have a Swift bridge, you can just include this in it:

#import <CommonCrypto/CommonHMAC.h>

This pulls in the SHA256 functions.

Portions of this - usually Objective C versons - taken from AlamoFire and AFNetworking

*/


class CertificatePinner {

    /**

        The base URL to check against when validateCertificateTrustChain is called.

    */
    public var expectedBaseUrl : String?


    /**

        Debug mode prints out the hashes on validation. Useful for finding out what the server is presenting
        so you have something to pin to

    */
    public var debugMode: Bool = false


    private var localHashList : [String] = []


    init() {

    }

    init(_ expectedUrl : String)  {
        expectedBaseUrl = expectedUrl
    }

    /**

        Add a hash to validate against.

        - Parameter hash: the hash string (eg "+abCS2zjVyISeEE90Fq1eC1ihAtQoh6q3mMUjlLGXfw=") to match

        Use debugMode to find the hashes

    */
    public func addCertificateHash(hash : String) {
        localHashList.append(hash)
    }


    /**

        Validates the certificate trust chain - we are expecing a certificate from google.com, did we get one?

        - Parameter trust: The trust provided by NSUrlSession and NSUrlConnection

        - Returns: true if the chain is valid.

    */
    public func validateCertificateTrustChain(trust: SecTrust) -> Bool {

        //https://github.com/Alamofire/Alamofire/blob/master/Source/ServerTrustPolicy.swift#L208

        guard let baseUrl = expectedBaseUrl where expectedBaseUrl != "" else {
            return false
        }

        let policy = SecPolicyCreateSSL(true, baseUrl as CFString)

        SecTrustSetPolicies(trust, policy)

        //https://github.com/Alamofire/Alamofire/blob/master/Source/ServerTrustPolicy.swift#L238
        var result = SecTrustResultType(kSecTrustResultInvalid)

        if SecTrustEvaluate(trust, &result) == errSecSuccess {
            return (result == SecTrustResultType(kSecTrustResultUnspecified) || result == SecTrustResultType(kSecTrustResultProceed))
        }

        return false

    }

    /**
        Validate the trust's provided public keys against any provided hash values

        - Parameter trust: The trust provided by NSUrlSession or NSUrlConnection
        - Returns: true if the trust is valid - if the hash of the provided public key (in the trust) matches a pre-defined hash.

        It is STRONGLY recommended that you DO NOT pin to your certificate - instead, pin the the parent of your certificate
        so that when you have to reissue your certificate, you can nothing breaks.

        If you don't expect to have long living app versions - you can expect your users to upgrade in a timely fashion - you
        could pin to your certificate, and just make sure that there is a new version of the app out, pinning to a new
        certificate, well before the new one is put onto the server.

    */
    public func validateTrustPublicKeys(trust: SecTrust) -> Bool {


        let trustPublicKeys = getPublicKeysFromTrust(trust)


        //do we have anything to compare to?
        if trustPublicKeys.count == 0 {
            return false
        }

        if localHashList.count == 0 && !debugMode {
            print("You are using a certificate pinner, but have not provided anything to pin to! Turn debugMode on.")
            return true
        }

        if debugMode {
            print("hash order is usually most specific to least, so the first one is your domain, the last is the root CA")
            for trustKey in trustPublicKeys {
                print("hash: \(trustKey)")
            }
        }

        for trustKey in trustPublicKeys {
            for localKey in localHashList {
                if (localKey == trustKey) {
                    return true
                }
            }
        }

        return false

    }

    /**
        Get the public keys from a trust. loop over each certificate, get the public key out and hash it
    */
    private func getPublicKeysFromTrust(trust: SecTrust) -> [String] {

        //https://github.com/Alamofire/Alamofire/blob/master/Source/ServerTrustPolicy.swift#L274
        var res : [String] = []

        var publicKeys: [SecKey] = []

        for index in 0..<SecTrustGetCertificateCount(trust) {
            if let
                certificate = SecTrustGetCertificateAtIndex(trust, index),
                publicKey = publicKeyForCertificate(certificate)
            {
                let publicKeyHash = publicKeyRefToHash(publicKey)
                res.append(publicKeyHash)
            }
        }

        return res
    }

    /**
        Get a single public key (reference) from a given certificate
    */
    private func publicKeyForCertificate(certificate: SecCertificate) -> SecKey? {
        //https://github.com/Alamofire/Alamofire/blob/master/Source/ServerTrustPolicy.swift#L289
        var publicKey: SecKey?

        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)

        if let trust = trust where trustCreationStatus == errSecSuccess {
            publicKey = SecTrustCopyPublicKey(trust)
        }

        return publicKey
    }

    /**
        Convert a public key ref to a hash - this requires loading it into the keychain, then getting a reference to it
        as a NSData, then hashing the content of that.
    */
    private func publicKeyRefToHash(publicKeyRef: SecKeyRef) -> String {

        if let keyData = publicKeyRefToData(publicKeyRef) {

            var hash = [UInt8](count: Int(CC_SHA256_DIGEST_LENGTH), repeatedValue: 0)
            CC_SHA256(keyData.bytes, CC_LONG(keyData.length), &hash)
            let res = NSData(bytes: hash, length: Int(CC_SHA256_DIGEST_LENGTH))

            return res.base64EncodedStringWithOptions(NSDataBase64EncodingOptions.init(rawValue: 0))
        }

        return ""
    }


    /**
        Convert a public key ref into an NSData

        Only way to do this is to load the key into the Keychain, then read it back.
    */
    private func publicKeyRefToData(publicKeyRef: SecKeyRef) -> NSData? {
        let keychainTag = "X509_KEY"
        var publicKeyData : AnyObject?
        var putResult : OSStatus = noErr
        var delResult : OSStatus = noErr

        let putKeyParams : NSMutableDictionary = [
            kSecClass as! String : kSecClassKey,
            kSecAttrApplicationTag as! String : keychainTag,
            kSecValueRef as! String : publicKeyRef,
            kSecReturnData as! String : kCFBooleanTrue
        ]

        let delKeyParams : NSMutableDictionary = [
            kSecClass as! String : kSecClassKey,
            kSecAttrApplicationTag as! String : keychainTag,
            kSecReturnData as! String : kCFBooleanTrue
        ]

        //SecItemAdd takes an UnsafeMutablePointer<AnyObject?>, which means "pointer to AnyObject?"
        // took me bloody ages to work this one out :( but the & maps to UnsafeMutablePointer<T>
        putResult = SecItemAdd(putKeyParams as! CFDictionary, &publicKeyData)
        delResult = SecItemDelete(delKeyParams as! CFDictionary)

        if putResult != errSecSuccess || delResult != errSecSuccess {
            return nil
        }

        return publicKeyData as? NSData
    }



}
