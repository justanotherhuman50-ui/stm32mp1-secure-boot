SUMMARY = "Capstone OP-TEE remote attestation TA (evidence v1)"
LICENSE = "BSD-2-Clause"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/BSD-2-Clause;md5=cb641bc04cda31daea161b1bc15da69f"

DEPENDS = "virtual-optee-os python3-pycryptodomex-native python3-cryptography-native"

inherit python3native

SRC_URI = "file://Makefile \
           file://sub.mk \
           file://attestation_ta.c \
           file://attestation_ta.h \
           file://user_ta_header_defines.h \
          "

PV = "1.0"
S = "${WORKDIR}"

TA_DEV_KIT_DIR = "${STAGING_INCDIR}/optee/export-user_ta"

# LDFLAGS is emptied on purpose: the Yocto host-style ldflags break the TA link.
# TA signing uses TA_SIGN_KEY from the dev kit (keys/default_ta.pem, the public
# OP-TEE sample key) until the project key is generated (decision 5).
EXTRA_OEMAKE = " TA_DEV_KIT_DIR=${TA_DEV_KIT_DIR} \
                 CROSS_COMPILE=${TARGET_PREFIX} \
                 O=${B}/out \
                 LDFLAGS= \
                 V=1 \
               "

do_compile() {
    export CFLAGS="${CFLAGS} --sysroot=${STAGING_DIR_HOST}"
    export OPENSSL_MODULES="${STAGING_LIBDIR_NATIVE}/ossl-modules"
    oe_runmake
}

do_install() {
    install -d ${D}${nonarch_base_libdir}/optee_armtz
    install -p -m 0444 ${B}/out/*.ta ${D}${nonarch_base_libdir}/optee_armtz/
}

# TA binaries are not regular ELF: skip the GNU_HASH QA check
INSANE_SKIP:${PN} += "ldflags"

FILES:${PN} += "${nonarch_base_libdir}/optee_armtz/"

# Depends on the machine-specific OP-TEE dev kit in staging
PACKAGE_ARCH = "${MACHINE_ARCH}"
