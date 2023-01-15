import Foundation
import XCTest
@testable import _FA

class Base32Tests: XCTestCase {
    func testRfcInputs() {
        XCTAssertEqual(base32ToBytes(base32: "MY======"), Array("f".utf8))
        XCTAssertEqual(base32ToBytes(base32: "MZXQ===="), Array("fo".utf8))
        XCTAssertEqual(base32ToBytes(base32: "MZXW6==="), Array("foo".utf8))
        XCTAssertEqual(base32ToBytes(base32: "MZXW6YQ="), Array("foob".utf8))
        XCTAssertEqual(base32ToBytes(base32: "MZXW6YTB"), Array("fooba".utf8))
        XCTAssertEqual(base32ToBytes(base32: "MZXW6YTBOI======"), Array("foobar".utf8))
    }
}

class TotpTests: XCTestCase {
    private let seedFromRfc6238 = "3132333435363738393031323334353637383930".asBytes()
    private let periodFromRfc6238 = UInt64(30)
    private let t0FromRfc6238 = UInt64.zero
    private let codeLengthFromRfc6238 = 8

    func getActual(inputTs:UInt64) -> String {
        let t = (inputTs - t0FromRfc6238) / periodFromRfc6238
        return totp6(seedAsBytes: seedFromRfc6238, steps: t, codeLength: codeLengthFromRfc6238, algorithm: withSha1(message:key:))
    }
    
    func testTotpFromRfx() {
        XCTAssertEqual(getActual(inputTs: 59), "94287082")
        XCTAssertEqual(getActual(inputTs: 1111111109), "07081804")
        XCTAssertEqual(getActual(inputTs: 1111111111), "14050471")
        XCTAssertEqual(getActual(inputTs: 1234567890), "89005924")
        XCTAssertEqual(getActual(inputTs: 2000000000), "69279037")
        XCTAssertEqual(getActual(inputTs: 20000000000), "65353130")
    }
}
