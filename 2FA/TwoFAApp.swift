import Darwin
import Foundation
import LocalAuthentication

@main
struct X {
    static func main() {
        run()
    }
}

func run() {
    guard CommandLine.argc >= 2 else {
        fputs("Expected set or get command\n", stderr)
        exit(1)
    }
    let mode = CommandLine.arguments[1]

    switch mode {
    case "set":
        guard CommandLine.argc >= 4 else {
            fputs("Invalid set command, expected . set [key] [seed]\n", stderr)
            exit(1)
        }
        var password = CommandLine.arguments[3]
        if password == "-" {
            var buf = [CChar](repeating: 0, count: 256)
            guard let cpassword = readpassphrase("Seed (max 255 chars): ", &buf, buf.count, RPP_ECHO_OFF) else {
                fputs("Password required\n", stderr)
                exit(1)
            }
            password = String(cString: cpassword)
        }
        setNew(label: CommandLine.arguments[2], seed: password)
        exit(0)
    case "get":
        guard CommandLine.argc >= 3 else {
            fputs("Invalid get command, expected . get [key]\n", stderr)
            exit(1)
        }
        let seed = fetchSeed(label: CommandLine.arguments[2])
        print(totp6(seed: seed), terminator: "")
        exit(0)
    default:
        fputs("Unknown command mode: \(mode)\n", stderr)
        exit(1)
    }
}
