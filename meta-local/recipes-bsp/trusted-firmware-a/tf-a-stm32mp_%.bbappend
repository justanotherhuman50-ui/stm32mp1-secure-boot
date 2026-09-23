SIGN_ENABLE = "1"
SIGN_KEY_stm32mp15 = "/home/zybo/keys/stm32mp1-boot-signing/tfa_boot_ecdsa.pem"
SIGN_KEY_stm32mp13 = "/home/zybo/keys/stm32mp1-boot-signing/tfa_boot_ecdsa.pem"
SIGN_TOOL = "cert_create"
EXTRA_OEMAKE += "KEY_ALG=ecdsa"
SIGN_TOOL_EXTRA_stm32mp15 += " -a ecdsa"

do_compile:prepend() {
    export PATH="/mnt/storage/stm32mp1-workspace/meta-local:${PATH}"
}
