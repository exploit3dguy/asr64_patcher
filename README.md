# asr64_patcher
A tool to patch the signature checks of a 64-bit ASR binary.

## Build
`make`

## Usage
1. Extract binary from an iOS ramdisk (macOS only):
    - `img4 -i <ramdisk> -o ramdisk.dmg`
        - `img4` can be found [here](https://github.com/xerub/img4lib)
    - `hdiutil attach ramdisk.dmg -mountpoint ramdisk`
    - `cp ramdisk/usr/sbin/asr .`
    - `hdiutil detach ramdisk`

2. Run `asr64_patcher`:
    - `asr64_patcher asr asr_patched`

3. Resign patched ASR binary
    - `ldid -e asr > ents.plist`
    - `ldid -Sents.plist asr_patched`