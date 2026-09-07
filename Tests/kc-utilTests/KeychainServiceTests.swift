import Testing
@testable import kc_util

struct KeychainServiceTests {

    @Test("验证无效格式或不存在的指纹查询不会崩")
    func testInvalidFingerprintLength() throws {
        let invalidFP = "12345" // 长度既不是 40 (SHA-1) 也不是 64 (SHA-256)
        
        // 验证执行时抛出 invalidFingerprintLength 错误，而不是崩溃
        #expect(throws: KeychainError.invalidFingerprintLength) {
            try KeychainService.findCertificates(fingerprint: invalidFP)
        }
    }
}