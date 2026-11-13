Unofficial build of iloader with iPad/iPhone support.

## What's new
- **iloader runs on iPad/iPhone** (`iloader-ios-unsigned.ipa`, install with SideStore or LiveContainer).
- **Install apps over Wi-Fi** on other devices on the same network.
- **Pair without a computer (iOS/iPadOS 27+)**: Settings → Developer Mode → pair with "iloader" and enter the PIN.
- **SideStore-style sign-in** with fallback anisette servers.
- **Move your sign-in from a computer to the iPad**: Export on the desktop app, Import on the iPad. The export file contains your password, so keep it private and delete it after importing.
- Increased Memory Limit is added to every app iloader signs.

## Notes
- If sign-in fails with HTTP 503, Apple is blocking your network. Turn on a VPN (for example 1.1.1.1) while signing in and signing apps.
- iOS runs one VPN at a time: to install on the iPad itself you need LocalDevVPN, so switch to it after signing in.
- Tick "Save credentials" when signing in, or the account won't stay in the saved list.
- The macOS DMG is from a slightly older commit (920fe82); everything else is from a537125.
