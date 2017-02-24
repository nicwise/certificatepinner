# Certificate Pinner

A Swift implementation of certificate pinning which works with `NSURLSession` and `NSURLConnection`

The [full blog post is located here](https://fastchicken.co.nz/2016/03/21/increasing-your-trust-certificate-pinning-on-ios).

> 2017-01-09: Updated for Swift 3.0. If you want [Swift 2.0 its now under a tag.](https://github.com/nicwise/certificatepinner/tree/swift2.0)

Certificate Pinning can be quite difficult if you are not using [AlamoFire](https://github.com/Alamofire/Alamofire) or [AFNetworking](https://github.com/AFNetworking/AFNetworking), as iOS doesn't expose any API's to get the certificate information out. The normal solution is to pull in bits of openssl, but to be honest, thats overkill.

Hence this library. Oh how much time it would have saved us (me) if someone else had done this.

# A note about what to pin to

Have a look at the GitHub certificate information - click on the lock. You should see _three_ (or more) levels of certificates.

* github.com - this is "their" certificate, or the leaf certificate
* DigiCert SHA2 Extended Validation Server CA - this is the leaf node of the Certificate Authority
* DigiCert High Assurance EV Root CA - this is the root certificate, which also lives inside your browsers trusted certificate list

You can pin to any of these, but I recommend the following:

* If you have an app which is updated often, and you can expect your users to update quickly, you can consider pinning to your leaf (github.com). This expires after 24 months, usually, so you'll be maintaining a short list of hashs
* If you have an app which isn't updated often, or you know your users may stick on an old version for a while, consider pinning to the leaf node of your CA (DigiCert SHA2 Extended Validation Server CA). This is almost as secure as your leaf node, especially if you have an EV or other hard-to-get certificate - or your own self-signed certificate chain. If the CA's certificate is compromised, it would invalidate your leaf node anyway - and these usually expire after 25-30 years.
* There is no reason to pin to the root, ever. Way too easy to get these.

We choose to pin to the CA leaf node, after conversations with our penitration testers and security people. Highest security for least risk. Note that pinning doesn't _stop_ someone from MITM proxying your app if they have access to the device, but it does stop it if they don't. Don't trust this to super secret secrets - it's just one tool amongst many.

# Usage

To use this, have a look in `CertificatePinningTest/ViewController.swift`. The crux of it is:

##Setup

You need to setup the pinner with one or more hashes, and (if you want to validate it) the source domain name.

```
    func setupCertificatePinner() -> CertificatePinner {
        var pinner = CertificatePinner("www.google.co.nz")

        pinner.debugMode = true
        pinner.addCertificateHash("+abCS2zjVyISeEE90Fq1eC1ihAtQoh6q3mMUjlLGXfw=")

        return pinner
    }
```

## NSURLSession

`NSUrlSession` is the new hottness from iOS7 onwards. You should be using it.

```
	func nsUrlSessionTapped(sender: UIButton) {
        let url = NSURL(string: "https://www.google.co.nz")

        let session = NSURLSession(
       	 	configuration: NSURLSessionConfiguration.ephemeralSessionConfiguration(),
            delegate: self,
            delegateQueue: nil)


        let task = session.dataTaskWithURL(url!) {
            (data, response, error) in
            if error != nil {
                print("error....")
            } else {
                print("done")
            }
        }

        task.resume()

    }
```

Once it's started, you need to implement `NSURLSessionDelegate`, and implement `didReceiveChallenge`

```
	func URLSession(session: NSURLSession, didReceiveChallenge challenge: NSURLAuthenticationChallenge, completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Void) {
        print("being challanged! for \(challenge.protectionSpace.host)")

        guard let trust = challenge.protectionSpace.serverTrust else {
            print("invalid trust!")
            completionHandler(.CancelAuthenticationChallenge, nil)
            return
        }


        let credential = NSURLCredential(trust: trust)

        let pinner = setupCertificatePinner()

        if (!pinner.validateCertificateTrustChain(trust)) {
            print("failed: invalid certificate chain!")
            challenge.sender?.cancelAuthenticationChallenge(challenge)
        }

        if (pinner.validateTrustPublicKeys(trust)) {
            completionHandler(.UseCredential, credential)

        } else {
            print("couldn't validate trust for \(challenge.protectionSpace.host)")
            completionHandler(.CancelAuthenticationChallenge, nil)
        }
    }
```

## NSURLConnection

`NSURLConnection` has been deprecated by Apple, but it's still there. Really. Somewhere.

You need to kick off an `NSURLConnection` in the same manner as you normally would, but provide a delegate:

```
	func nsUrlConnectionTapped(sender: UIButton) {
	    let request = NSMutableURLRequest(URL: NSURL(string: "https://www.google.co.nz")!)
	    let conn = NSURLConnection(request: request, delegate: self, startImmediately: true)
	}
```

You then implement `NSURLConnectionDelegate`, and override `willSendRequestForAuthenticationChallenge`:

```
    func connection(connection: NSURLConnection, willSendRequestForAuthenticationChallenge challenge: NSURLAuthenticationChallenge) {
        print("being challanged! for \(challenge.protectionSpace.host)")

        guard let trust = challenge.protectionSpace.serverTrust else {
            print("invalid trust!")
            challenge.sender?.cancelAuthenticationChallenge(challenge)
            return
        }



        let credential = NSURLCredential(trust: trust)

        let pinner = setupCertificatePinner()

        if (!pinner.validateCertificateTrustChain(trust)) {
            print("failed: invalid certificate chain!")
            challenge.sender?.cancelAuthenticationChallenge(challenge)
        }

        if (pinner.validateTrustPublicKeys(trust)) {
            challenge.sender?.useCredential(credential, forAuthenticationChallenge: challenge)
        } else {
            print ("couldn't validate trust for \(challenge.protectionSpace.host)")
            challenge.sender?.cancelAuthenticationChallenge(challenge)
        }

    }

```

This implementation errs on the side of "reject if anything looks wrong".


## Local Certificate File
It might well be, that you have a certificate file that is not deployed online. You can calculate the public key hash of a certificate file using the `hashForDERCertificate(: Data)` function:

```swift
let pinner = CertificatePinner()
    
//read in sample DER certificate
let derURL = Bundle.main.url(forResource: "google_co_nz", withExtension: "der")!
let derData = try! Data(contentsOf: derURL)
if let hash = pinner.hashForDERCertificate(derData: derData) {
    print("SHA256 hash for \(derURL):\n\(hash)\n\n")
} else {
    print("Could not calculate hash for \(derURL)\n\n")
}
```

Tip: You can easily get the DER file of a website's certificate by showing the certificate details in Firefox. There will be a export button to save the certificate in CER or DER format.


# Thanks

Big props to the [AlamoFire](https://github.com/Alamofire/Alamofire) and [AFNetworking](https://github.com/AFNetworking/AFNetworking) teams, where the bulk of the code came from - this is mostly an extraction and replementation in Swift of their code, with a bit of opinion added for good measure.
