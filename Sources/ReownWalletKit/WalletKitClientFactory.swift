import Foundation

struct WalletKitClientFactory {
    static func create(
        signClient: SignClientProtocol,
        pairingClient: PairingClientProtocol,
        pushClient: PushClientProtocol,
        config: WalletKit.Config,
        projectId: String? = nil
    ) -> WalletKitClient {
        return WalletKitClient(
            signClient: signClient,
            pairingClient: pairingClient,
            pushClient: pushClient
        )
    }
}
