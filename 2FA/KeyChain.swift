import Darwin
import Foundation
import LocalAuthentication

func setNew(label: String, seed: String) -> Void {
    let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleWhenUnlocked, .userPresence, nil)
    let context = LAContext()
    context.touchIDAuthenticationAllowableReuseDuration = 5
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccount as String: "2fa_seed_" + label,
        kSecAttrLabel as String: "2fa_seed_" + label,
        kSecAttrAccessControl as String: access!,
        kSecUseAuthenticationContext as String: context,
        kSecUseDataProtectionKeychain as String: true,
        kSecValueData as String: seed.data(using: .utf8)!,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)
    switch status {
    case errSecSuccess:
        print("Set seed for \(label)")
        return
        
    case errSecDuplicateItem:
        print("Found existing seed for \(label) - will update to new seed")
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecMatchLimit as String: kSecMatchLimitOne,
            kSecAttrAccount as String: "2fa_seed_" + label,
            kSecAttrLabel as String: "2fa_seed_" + label,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        let attrsToUpdate: [String: Any] = [
            kSecValueData as String: seed.data(using: .utf8)!,
        ]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, attrsToUpdate as CFDictionary)
        guard updateStatus == errSecSuccess else { fputs("Could not update seed for \(label): \(String(updateStatus))\n", stderr); exit(1) }
        print("Updated seed for \(label)")
        return
        
    default:
        fputs("Could not write seed into keychain: \(String(status))\n", stderr);
        exit(1)
    }
}


func fetchSeed(label: String) -> String {
    let context = LAContext()
    context.localizedReason = "Authenticate to read 2FA seed"
    context.touchIDAuthenticationAllowableReuseDuration = 5
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecMatchLimit as String: kSecMatchLimitOne,
        kSecAttrAccount as String: "2fa_seed_" + label,
        kSecAttrLabel as String: "2fa_seed_" + label,
        kSecReturnAttributes as String: true,
        kSecReturnData as String: true,
        kSecUseAuthenticationContext as String: context,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status != errSecItemNotFound else { fputs("Could not find item \(label) in keychain\n", stderr); exit(1) }
    guard status == errSecSuccess else { fputs("Unknown error accessing keychain: \(String(status))\n", stderr); exit(1); }
    
    guard let existingItem = item as? [String: Any],
          let data = existingItem[kSecValueData as String] as? Data,
          let seed = String(data: data, encoding: String.Encoding.utf8)
    else { fputs("Malformed keychain data - perhaps delete and re-add this seed\n", stderr); exit(1) }

    return seed
}
