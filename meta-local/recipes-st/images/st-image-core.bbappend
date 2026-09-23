# The ST flashlayout templates derive TF-A/FIP filenames from SIGN_ENABLE.
# Keep this scoped to the image recipe so generated TSVs reference signed
# boot artifacts produced by tf-a-stm32mp and fip-stm32mp.
SIGN_ENABLE = "1"
