# STM32MP15 Trusted Board Boot Investigation

## Status

- Target: STM32MP157D-DK1, D-tier/open silicon.
- ROTPK/PKH OTP: blank and undeployed.
- Expected message: `ROTPK is not deployed on platform. Skipping ROTPK verification.`
- Meaning: the platform-ROTPK comparison is skipped. This message alone does
  not prove that all downstream authentication is skipped.
- Important platform finding: the STM32MP1 crypto backend has a separate
  open-device capability gate. On an open device for which
  `stm32mp_is_auth_supported()` is false, its signature verifier returns
  `CRYPTO_SUCCESS` before mbedTLS signature verification.
- The detected part is `STM32MP157DAC`; the current source's support table
  contains `STM32MP157C` and `STM32MP157F`, but not `STM32MP157DAC`.
  Therefore this is the leading explanation for “implemented but not
  enforced” on the present board.

## Current diagnosis

`-80` at `BL2: Failed to load image id ...` is the generic `-EAUTH` returned by
`common/bl_common.c` after an underlying authentication error. It is not, by
itself, evidence of an ECDSA failure, SHA-256 failure, ROTPK mismatch, or X.509
parser failure.

The current boot log does not show `-80`; it boots through BL32, U-Boot, and
Linux. It also contains no `[AUTH-DIAG]` lines, and the running BL2 identifies
itself as built on Jun 28 2024. That deployed binary is therefore not evidence
that the instrumented source currently in the workspace was flashed.

The more important source-level result is:

```text
plat/st/stm32mp1/stm32mp1_private.c:553
    stm32mp_is_auth_supported()
    STM32MP157C/F are listed; STM32MP157DAC is not

plat/st/common/stm32mp_crypto_lib.c:325-328
    if (open device && !stm32mp_is_auth_supported())
        return CRYPTO_SUCCESS;
```

This means the generic chain-of-trust code can be present and entered while
the platform crypto callback deliberately converts signature verification into
success on this open DAC device. The two ROTPK messages are not themselves the
whole cause; the unsupported-part-number gate is the actionable cause now
identified. Hardware BootROM authentication is also absent, as shown by
`Bootrom authentication failed`, so BL2 itself is not hardware anchored.

Authentication path:

```text
bl2_load_images()
  -> load_auth_image()
  -> load_auth_image_recursive()
  -> auth_mod_verify_img(img_id, image, length)
  -> img_parser_check_integrity()
  -> auth_hash() or auth_signature()
  -> crypto_mod_verify_hash() or crypto_mod_verify_signature()
  -> mbedTLS
```

Relevant source files:

- `tmp-glibc/work-shared/stm32mp1/tfa-source/bl2/bl2_image_load_v2.c`
- `tmp-glibc/work-shared/stm32mp1/tfa-source/common/bl_common.c`
- `tmp-glibc/work-shared/stm32mp1/tfa-source/drivers/auth/auth_mod.c`
- `tmp-glibc/work-shared/stm32mp1/tfa-source/drivers/auth/mbedtls/mbedtls_x509_parser.c`
- `tmp-glibc/work-shared/stm32mp1/tfa-source/drivers/auth/mbedtls/mbedtls_crypto.c`

## Diagnostic state

The checked-out TF-A source already contains `[AUTH-DIAG]` logging for:

- authentication `img_id` and image type;
- parser parameter extraction failures;
- mbedTLS algorithm ASN.1 decoding;
- public-key parsing;
- signature BIT STRING parsing;
- digest calculation;
- raw ECDSA/public-key verification;
- final crypto return code.

No cryptographic behavior or authentication policy has been changed by this
investigation entry. The next source change must be isolated to this platform
capability decision, then tested with a known-good signed FIP and a one-byte
payload tamper. It must not touch OTP, closure, certificate generation, or
ROTPK handling.

## This turn

The user supplied the complete current boot log. It shows:

- `Bootrom authentication failed`;
- `TRUSTED_BOARD_BOOT support enabled`;
- two `ROTPK is not deployed on platform` messages;
- `BL2: Booting BL32`, followed by OP-TEE, U-Boot, Linux, and systemd;
- no authentication diagnostics in the deployed BL2.

Source inspection then found the STM32MP15 capability mismatch and the
`CRYPTO_SUCCESS` early return described above. This explains why a signed or
altered downstream image can currently boot without proving its signature was
checked on this DAC/open configuration.

The first controlled source change has now been applied in the work-shared
TF-A source: `STM32MP157D_PART_NB` was added to the existing
`stm32mp_is_auth_supported()` cases. This causes the existing STM32MP15 ROM
ECDSA callback to be initialized instead of taking the unsupported-part
`CRYPTO_SUCCESS` path. It is not yet validated on hardware.

Next: deploy the newly compiled TF-A through the normal full-image flow, then
capture UART. If the ROM callback is
not usable on D-tier, the boot result will identify that boundary; no OTP or
certificate change is appropriate until then.

## Safety constraints

- Do not burn OTPs.
- Do not close the device.
- Do not change signing algorithms, keys, certificate contents, or ROTPK logic
  while localizing `-80`.
- Do not claim hardware-rooted secure boot on this board.

## Evidence log

| Date | Evidence | Interpretation |
|---|---|---|
| 2026-09-22 | Two `ROTPK is not deployed on platform` notices | Expected open-device behavior; root-key comparison skipped only |
| 2026-09-22 | `-80` reported previously | Generic `-EAUTH`; underlying failure remains unknown |
| 2026-09-22 | Current log says `Bootrom authentication failed` but reaches BL32/U-Boot/Linux | BL2 is not hardware-authenticated; full boot alone does not prove FIP image verification |
| 2026-09-22 | Source omits `STM32MP157DAC` from `stm32mp_is_auth_supported()` | DAC is treated as unsupported by the platform capability function |
| 2026-09-22 | `stm32mp_crypto_lib.c` returns `CRYPTO_SUCCESS` for open + unsupported auth | Signature verification is bypassed before mbedTLS in the current platform path |
| 2026-09-22 | Added `STM32MP157D_PART_NB` to `stm32mp_is_auth_supported()` | First controlled fix attempt; enables the existing ROM ECDSA callback path |
| 2026-09-22 | `bitbake -c compile -f tf-a-stm32mp` completed successfully | Modified TF-A source compiled; deployment, FIP regeneration, flashing, and runtime enforcement are not yet proven |
| 2026-09-22 | `bitbake -c deploy -f tf-a-stm32mp` completed successfully | Deployment task passed; forced-task taint warnings are expected, and D-board signed TF-A artifacts were regenerated at `tmp-glibc/deploy/images/stm32mp1/arm-trusted-firmware/` |
| 2026-09-22 | Four warnings during deploy | Two are forced-task taint notices; two are the existing `ST_TF_A_DEBUG_TRACE` signing-class warning. None caused task failure |
| 2026-09-22 | `bitbake st-image-weston` completed with 127 warnings and no task failures | Full image build succeeded; warnings include forced-task taints, repeated signing/debug notices, one unrelated netdata build-path QA warning, and missing flash-layout variants |
| 2026-09-22 | Generated `fip/fip-stm32mp157d-dk1-optee-sdcard_Signed.bin` and DK1 TF-A artifacts | The board-specific signed SD-card FIP exists; the programmer-USB flash-layout warnings do not prevent this target artifact from being produced |
| 2026-09-22 | Timestamp audit completed | Signed TF-A artifacts: 19:03; signed DK1 FIPs and OP-TEE/U-Boot: 19:05; Weston rootfs: 19:31; kernel and kernel DTBs: 2026-08-15 15:27 |
| 2026-09-22 | Created `stm32mp157d-dk1-boot-artifacts-20260922.zip` | SCP bundle contains 52 DK1/D-tier boot artifacts plus this investigation log; about 200 MiB compressed, 724 MiB uncompressed |
| 2026-09-22 | Created `stm32mp157d-dk1-boot-artifacts-complete-20260922.zip` | Corrected bundle includes `metadata.bin`, all available DK1 core flash-layout TSVs, bootfs/core/userfs/vendorfs images, the new Weston rootfs, and the signed boot artifacts; 4.1 GiB ZIP |
