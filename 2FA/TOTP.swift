import Foundation
import Crypto

func totp6(seed: String) -> String {
    let seedAsBytes = base32ToBytes(base32: seed)
    return totp6(seedAsBytes: seedAsBytes, steps: UInt64(Date.now.timeIntervalSince1970 / 30), codeLength: 6, algorithm: withSha1(message:key:))
}

func totp6(seedAsBytes: [UInt8], steps: UInt64, codeLength: Int, algorithm: ([UInt8], SymmetricKey) -> [UInt8]) -> String {
    return getCode(seed: seedAsBytes, steps: steps, codeLength: codeLength, algorithm: algorithm)
}

let BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8.withIndex()
let BASE32_ALPHABET_MAP = Dictionary(uniqueKeysWithValues: BASE32_ALPHABET)
func base32ToBytes(base32: String) -> [UInt8] {
    let sanitised = base32.trimmingCharacters(in: ["="]).uppercased().utf8
    let asOffsets = sanitised.map({ BASE32_ALPHABET_MAP[$0] ?? -1 })
    asOffsets.forEach { if $0 < 0 { fputs("Invalid base32 string\n", stderr); exit(1) } }
    let in8s:[[Int]] = asOffsets.chunked(size: 8)
    let in5s = in8s.map {
        let block = [$0.getOr0(0), $0.getOr0(1), $0.getOr0(2), $0.getOr0(3), $0.getOr0(4), $0.getOr0(5), $0.getOr0(6), $0.getOr0(7)]
        return shiftedBlock(block: block)
    }
    let in5s2 = in5s.flatMap { $0 }
    let truncateTo = in5s2.lastIndex(where: {$0 != 0})!
    let truncated = Array(in5s2[0...truncateTo])
    return truncated
}

func shiftedBlock(block:[UInt32]) -> [UInt8] {
    // 00000111 11222223 33334444 45555566 66677777
    let a = ((block[0] & 0b11111) << 3) | ((block[1] & 0b11100) >> 2)
    let b = ((block[1] & 0b00011) << 6) | ((block[2] & 0b11111) << 1) | ((block[3] & 0b10000) >> 4)
    let c = ((block[3] & 0b01111) << 4) | ((block[4] & 0b11110) >> 1)
    let d = ((block[4] & 0b00001) << 7) | ((block[5] & 0b11111) << 2) | ((block[6] & 0b11000) >> 3)
    let e = ((block[6] & 0b00111) << 5) | (block[7] & 0b11111)
    return [UInt8(a),UInt8(b),UInt8(c),UInt8(d),UInt8(e)]
}


func getCode(seed: [UInt8], steps: UInt64, codeLength: Int, algorithm: ([UInt8], SymmetricKey) -> [UInt8]) -> String {
    let key = SymmetricKey(data: seed)
    let str = steps.hex(length: 16).asBytes()
    let bytes = algorithm(str, key)
    let last4 = bytes.last4Bits()
    let intAtPos = bytes.intAtPosition(offset: last4)
    return Int(intAtPos & 0x7fffffff).lastDigits(length: codeLength)
}


func withSha1(message: [UInt8], key: SymmetricKey) -> [UInt8] {
    let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(message), using: key)
    var bytes = [UInt8]()
    hmac.withUnsafeBytes { bytes.append(contentsOf: $0) }
    return bytes
}

extension Collection {
    public func withIndex() -> any Collection<(Self.Element, Int)> {
        var i = -1
        return self.map({
            i += 1
            return ($0, i)
        })
    }
}


extension Array<Int> {
    public func getOr0(_ i: Int) -> UInt32 {
        return (i >= self.endIndex) ? UInt32.zero : UInt32(self[i])
    }
    public func chunked(size: Int) -> Array<Array<Self.Element>> {
        var result:[[Int]] = []
        var i = self.startIndex
        while (i < self.endIndex) {
            let chunkSize = size.coerce(atMost: self.count - i)
            let nextChunk = Array(self[i..<(i+chunkSize)])
            result.append(nextChunk)
            i += size
        }
        return result
    }
}

extension Int {
    public func coerce(atMost: Int) -> Int {
        return (self > atMost) ? atMost : self
    }
    public func lastDigits(length: Int) -> String {
        let POWERS_OF_TEN = [1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000]
        return String(self % POWERS_OF_TEN[length]).padStart0(length: length)
    }
}

extension Array<UInt8> {
    public func last4Bits() -> Int {
        return Int(self.last! & 0x0f)
    }
    public func intAtPosition(offset: Int) -> UInt32 {
        return ((UInt32(self[offset]) & 0xff) << 24) | ((UInt32(self[offset+1]) & 0xff) << 16) | ((UInt32(self[offset+2]) & 0xff) << 8) | (UInt32(self[offset+3]) & 0xff)
    }
}

extension UInt64 {
    public func hex(length: Int) -> String {
        return String(self, radix: 16).padStart0(length: length)
    }
}


extension String {
    public func asBytes() -> [UInt8] {
        var i = self.startIndex
        var result = [UInt8]()
        while i < self.endIndex {
            let nextI = self.index(i, offsetBy: 2)
            result.append(UInt8(self[i..<nextI], radix:16)!)
            i = nextI
        }
        return result
    }
    public func padStart0(length: Int) -> String {
        return String(String(self.reversed()).padding(toLength: length, withPad: "0", startingAt: 0).reversed())
    }
}
