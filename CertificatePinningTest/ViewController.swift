//
//  ViewController.swift
//  CertificatePinningTest
//
//  Created by Nic Wise on 1/03/16.
//  Copyright (c) 2016 None. All rights reserved.
//


import UIKit


class ViewController: UIViewController {


    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view, typically from a nib.
    }


    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    func setupCertificatePinner() -> CertificatePinner {
        var pinner = CertificatePinner("www.google.co.nz")

        pinner.debugMode = true
        pinner.addCertificateHash("+abCS2zjVyISeEE90Fq1eC1ihAtQoh6q3mMUjlLGXfw=")

        return pinner
    }



    //------ NSURLConnection variant (deprecated, but used a lot)
    @IBAction func nsUrlConnectionTapped(sender: UIButton) {

        let request = NSMutableURLRequest(URL: NSURL(string: "https://www.google.co.nz")!)

        let conn = NSURLConnection(request: request, delegate: self, startImmediately: true)

    }



    //------------ NSURLSesssion variant

    @IBAction func nsUrlSessionTapped(sender: UIButton) {
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



}

extension ViewController : NSURLConnectionDelegate {
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
}

extension ViewController : NSURLConnectionDataDelegate {
    func connectionDidFinishLoading(connection: NSURLConnection) {
        print("all done")
    }
}

extension ViewController : NSURLSessionDelegate {
    @available(iOS 7.0, *) func URLSession(session: NSURLSession, didReceiveChallenge challenge: NSURLAuthenticationChallenge, completionHandler: (NSURLSessionAuthChallengeDisposition, NSURLCredential?) -> Void) {
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
}
