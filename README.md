# Certificate Pinner

A Swift implementation of certificate pinning which works with NSURLSession and NSURLConnection

The [full blog post is located here]().

Certificate Pinning can be quite difficult if you are not using [AlamoFire](https://github.com/Alamofire/Alamofire) or [AFNetworking](https://github.com/AFNetworking/AFNetworking), as iOS doesn't expose any API's to get the certificate information out. The normal solution is to pull in bits of openssl, but to be honest, thats overkill.

Hence this library. Oh how much time it would have saved us (me) if someone else had done this.

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

# Thanks

Big props to the [AlamoFire](https://github.com/Alamofire/Alamofire) and [AFNetworking](https://github.com/AFNetworking/AFNetworking) teams, where the bulk of the code came from - this is mostly an extraction and replementation in Swift of their code, with a bit of opinion added for good measure.