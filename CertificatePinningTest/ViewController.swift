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
    @IBAction func nsUrlConnectionTapped(_ sender: UIButton) {

        let request = NSMutableURLRequest(url: URL(string: "https://www.google.co.nz")!)

        let conn = NSURLConnection(request: request as URLRequest, delegate: self, startImmediately: true)

    }



    //------------ NSURLSesssion variant

    @IBAction func nsUrlSessionTapped(_ sender: UIButton) {
        let url = URL(string: "https://www.google.co.nz")

        let session = Foundation.URLSession(
        configuration: URLSessionConfiguration.ephemeral,
                delegate: self,
                delegateQueue: nil)


        let task = session.dataTask(with: url!, completionHandler: {
            (data, response, error) in
            if error != nil {
                print("error....")
            } else {
                print("done")
            }
        }) 

        task.resume()

    }



}

extension ViewController : NSURLConnectionDelegate {
    func connection(_ connection: NSURLConnection, willSendRequestFor challenge: URLAuthenticationChallenge) {
        print("being challanged! for \(challenge.protectionSpace.host)")

        guard let trust = challenge.protectionSpace.serverTrust else {
            print("invalid trust!")
            challenge.sender?.cancel(challenge)
            return
        }



        let credential = URLCredential(trust: trust)

        let pinner = setupCertificatePinner()

        if (!pinner.validateCertificateTrustChain(trust)) {
            print("failed: invalid certificate chain!")
            challenge.sender?.cancel(challenge)
        }

        if (pinner.validateTrustPublicKeys(trust)) {
            challenge.sender?.use(credential, for: challenge)
        } else {
            print ("couldn't validate trust for \(challenge.protectionSpace.host)")
            challenge.sender?.cancel(challenge)
        }

    }
}

extension ViewController : NSURLConnectionDataDelegate {
    func connectionDidFinishLoading(_ connection: NSURLConnection) {
        print("all done")
    }
}

extension ViewController : URLSessionDelegate {
    @available(iOS 7.0, *) func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        print("being challanged! for \(challenge.protectionSpace.host)")

        guard let trust = challenge.protectionSpace.serverTrust else {
            print("invalid trust!")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }


        let credential = URLCredential(trust: trust)

        let pinner = setupCertificatePinner()

        if (!pinner.validateCertificateTrustChain(trust)) {
            print("failed: invalid certificate chain!")
            challenge.sender?.cancel(challenge)
        }

        if (pinner.validateTrustPublicKeys(trust)) {
            completionHandler(.useCredential, credential)

        } else {
            print("couldn't validate trust for \(challenge.protectionSpace.host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
