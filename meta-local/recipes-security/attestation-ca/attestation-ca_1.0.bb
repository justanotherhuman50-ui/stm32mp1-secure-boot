SUMMARY = "Capstone OP-TEE remote attestation TA test client (evidence v1)"
LICENSE = "BSD-2-Clause"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/BSD-2-Clause;md5=cb641bc04cda31daea161b1bc15da69f"

DEPENDS = "optee-client"

# attestation_ta.h is a symlink to ../attestation-ta/files/attestation_ta.h
# (one source of truth for the TA/CA interface). Two ways NOT to share it:
# - FILESEXTRAPATHS: extra paths are searched before this recipe's own files/,
#   and attestation-ta/files/ has a Makefile that would win.
# - an absolute file:// path: it unpacks under WORKDIR/mnt/..., so -I. misses it.
SRC_URI = "file://Makefile \
           file://attest_ca.c \
           file://attestation_ta.h \
           file://attest_pubkey.c \
          "

PV = "1.0"
S = "${WORKDIR}"

do_compile() {
    oe_runmake
}

do_install() {
    install -d ${D}${bindir}
    install -m 0755 ${B}/attest_ca ${D}${bindir}/attest_ca
    install -m 0755 ${B}/attest_pubkey ${D}${bindir}/attest_pubkey
}
