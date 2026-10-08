// SPDX-License-Identifier: Apache-2.0
// synthe-touchid: approvals signed by a key in this Mac's Secure Enclave, released only by Touch ID.
//
//   synthe-touchid available               exit 0 if this Mac can (Secure Enclave + enrolled Touch ID)
//   synthe-touchid create KEYFILE          make a new key; KEYFILE gets its public half and an opaque
//                                          handle only this Mac's Secure Enclave can use (0600, never
//                                          overwritten). Prints the public key (base64url x||y).
//   synthe-touchid sign KEYFILE REASON     read the bytes to sign on stdin; show REASON in the Touch ID
//                                          prompt; print the ES256 signature (base64url r||s).
//
// The private key never leaves the Secure Enclave, and it signs only after a successful Touch ID check
// with the fingerprints enrolled when it was made (.biometryCurrentSet: enrolling a new finger later
// disables it). Not even root can sign without a finger on the sensor. Exit codes: 0 ok, 2 usage,
// 3 unavailable, 4 not approved (cancelled or failed), 5 key file problem, 1 anything else.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func fail(_ message: String, _ code: Int32 = 1) -> Never {
    FileHandle.standardError.write(("synthe-touchid: " + message + "\n").data(using: .utf8)!)
    exit(code)
}

func b64u(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

func biometricsReady() -> (Bool, String) {
    guard SecureEnclave.isAvailable else { return (false, "this Mac has no Secure Enclave") }
    let context = LAContext()
    var error: NSError?
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) { return (true, "") }
    return (false, error?.localizedDescription ?? "Touch ID isn't available")
}

let args = CommandLine.arguments
guard args.count >= 2 else { fail("usage: synthe-touchid available | create KEYFILE | sign KEYFILE REASON", 2) }

switch args[1] {
case "available":
    let (ready, why) = biometricsReady()
    if !ready { fail(why, 3) }
    print("yes")

case "create":
    guard args.count == 3 else { fail("usage: synthe-touchid create KEYFILE", 2) }
    let (ready, why) = biometricsReady()
    if !ready { fail(why, 3) }
    let path = args[2]
    var cfError: Unmanaged<CFError>?
    guard let access = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], &cfError)
    else { fail("can't set the key's access control: \(String(describing: cfError?.takeRetainedValue()))") }
    let key: SecureEnclave.P256.Signing.PrivateKey
    do { key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access) } catch {
        fail("the Secure Enclave refused to make a key: \(error)")
    }
    let record: [String: String] = [
        "kind": "synthe-touchid-key", "alg": "ES256",
        "public_key": b64u(key.publicKey.rawRepresentation),
        "se_handle": key.dataRepresentation.base64EncodedString(),
    ]
    let json = try! JSONSerialization.data(withJSONObject: record, options: [.prettyPrinted, .sortedKeys])
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    if fd < 0 { fail("won't overwrite \(path) (or can't create it)", 5) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    handle.write(json)
    handle.write("\n".data(using: .utf8)!)
    print(record["public_key"]!)

case "sign":
    guard args.count == 4 else { fail("usage: synthe-touchid sign KEYFILE REASON  (bytes to sign on stdin)", 2) }
    let reason = String(args[3].prefix(300))
    guard let raw = FileManager.default.contents(atPath: args[2]),
          let record = try? JSONSerialization.jsonObject(with: raw) as? [String: String],
          record["kind"] == "synthe-touchid-key", let blob = record["se_handle"].flatMap({ Data(base64Encoded: $0) })
    else { fail("\(args[2]) isn't a synthe-touchid key file", 5) }
    let message = FileHandle.standardInput.readDataToEndOfFile()
    if message.isEmpty { fail("nothing to sign on stdin", 2) }
    let context = LAContext()
    context.localizedCancelTitle = "Don't approve"
    context.localizedReason = reason
    let done = DispatchSemaphore(value: 0)
    var approved = false
    var why = ""
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { ok, error in
        approved = ok
        why = error?.localizedDescription ?? ""
        done.signal()
    }
    done.wait()
    if !approved { fail("not approved" + (why.isEmpty ? "" : ": \(why)"), 4) }
    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob, authenticationContext: context)
        let signature = try key.signature(for: message)
        print(b64u(signature.rawRepresentation))
    } catch { fail("the Secure Enclave didn't sign: \(error)") }

default:
    fail("unknown command \(args[1]); use available, create or sign", 2)
}
