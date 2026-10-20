// CR-1609: compromised eMudhra keys, including cross-signed certificates.
// Source: https://emudhra.we-have-a-problem.com/impacted-intermediates.json
// Keep the SDK copy identical; CompromisedCATrustTests verifies parity.
import Foundation
import Security
import CryptoKit

/// Adds a key denylist to normal platform trust evaluation; never replaces it.
enum CompromisedCATrust {
    static let blockedSPKIHashes: Set<String> = [
        "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B",
        "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F",
        "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0",
        "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8",
        "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30",
        "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41",
        "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105",
        "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6",
    ]

    /// All published compromised keys are P-384. CryptoKit reconstructs their
    /// standard SubjectPublicKeyInfo rather than relying on certificate identity.
    static func permits(_ certificate: SecCertificate) -> Bool {
        guard let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              let kind = attributes[kSecAttrKeyType as String] as? String,
              let bits = attributes[kSecAttrKeySizeInBits as String] as? Int else { return false }
        guard kind == kSecAttrKeyTypeECSECPrimeRandom as String, bits == 384 else { return true }
        guard let bytes = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let publicKey = try? P384.Signing.PublicKey(x963Representation: bytes) else { return false }
        let fingerprint = SHA256.hash(data: publicKey.derRepresentation)
            .map { String(format: "%02X", $0) }.joined()
        return !blockedSPKIHashes.contains(fingerprint)
    }

    static func evaluate(_ trust: SecTrust) -> Bool {
        // Preserve the caller's SSL hostname policy, expiry, chain and root checks.
        guard SecTrustEvaluateWithError(trust, nil) else { return false }
        if #available(iOS 15, macOS 12, watchOS 8, tvOS 15, *) {
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
                  !chain.isEmpty else { return false }
            return chain.allSatisfy { permits($0) }
        } else {
            let count = SecTrustGetCertificateCount(trust)
            guard count > 0 else { return false }
            return (0..<count).allSatisfy { index in
                guard let certificate = SecTrustGetCertificateAtIndex(trust, index) else { return false }
                return permits(certificate)
            }
        }
    }
}
