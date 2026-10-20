import Foundation

/// App-owned HTTP clients must use this session (or its challenge handler).
public enum ReownProtectedURLSession {
    public static let shared = URLSession(configuration: .default, delegate: TrustDelegate(), delegateQueue: nil)

    public static func make(configuration: URLSessionConfiguration) -> URLSession {
        URLSession(configuration: configuration, delegate: TrustDelegate(), delegateQueue: nil)
    }

    static func handle(
        _ challenge: URLAuthenticationChallenge,
        completion: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            completion(.performDefaultHandling, nil)
            return
        }
        guard let trust = challenge.protectionSpace.serverTrust, CompromisedCATrust.evaluate(trust) else {
            completion(.cancelAuthenticationChallenge, nil)
            return
        }
        completion(.useCredential, URLCredential(trust: trust))
    }

    private final class TrustDelegate: NSObject, URLSessionDelegate {
        func urlSession(
            _ session: URLSession,
            didReceive challenge: URLAuthenticationChallenge,
            completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {
            ReownProtectedURLSession.handle(challenge, completion: completionHandler)
        }
    }
}
