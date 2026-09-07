public struct CertificateSummary: Sendable {
    public let label: String
    public let issuer: String
    public let fingerprintSHA1: String

    public init(label: String, issuer: String, fingerprintSHA1: String) {
        self.label = label
        self.issuer = issuer
        self.fingerprintSHA1 = fingerprintSHA1
    }
}