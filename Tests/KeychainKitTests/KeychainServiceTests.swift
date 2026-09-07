import Testing
@testable import KeychainKit

struct KeychainServiceTests {
    @Test("验证无效格式或不存在的指纹查询不会崩")
    func testInvalidFingerprintLength() throws {
        #expect(throws: KeychainError.invalidFingerprintLength) {
            try KeychainService.findCertificates(fingerprint: "12345")
        }
    }
}