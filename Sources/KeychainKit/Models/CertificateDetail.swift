import Foundation

public struct CertificateDetail: Sendable {
    public let subject: String
    public let issuer: String
    public let serialNumber: String
    public let notBefore: Date?
    public let notAfter: Date?
    public let fingerprintSHA1: String
    public let fingerprintSHA256: String
    public let keychainPath: String

    public init(subject: String, issuer: String, serialNumber: String, notBefore: Date?, notAfter: Date?, fingerprintSHA1: String, fingerprintSHA256: String, keychainPath: String) {
        self.subject = subject
        self.issuer = issuer
        self.serialNumber = serialNumber
        self.notBefore = notBefore
        self.notAfter = notAfter
        self.fingerprintSHA1 = fingerprintSHA1
        self.fingerprintSHA256 = fingerprintSHA256
        self.keychainPath = keychainPath
    }
}