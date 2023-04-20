from lib.constants import (
    FlashInfo,
    PatchInfo,
    internal_path,
    ecu_control_module_identifier,
)
from lib.crypto import aes

from .simosshared import (
    block_identifiers_simos,
    block_checksums_simos,
    box_code_location_simos,
    software_version_location_simos,
    block_transfer_sizes_simos,
    block_name_to_int,
    checksum_block_location,
)

def s12_block_transfer_sizes_patch(block_number: int, address: int) -> int:
    if block_number != 3:
        print(
            "Only patching __0006's Block 1 using a provided patch is supported at this time! If you have a patch for another block, please fill in its data areas here."
        )
        exit()
    if address < 0x44900:
        return 0x200
    if address >= 0x44900 and address < 0x44B00:
        return 0x8
    if address >= 0x44A00 and address < 0x99200:
        return 0x100
    if address >= 0x99200 and address < 0x99700:
        return 0x8
    if address >= 0x99700 and address < 0xBFB00:
        return 0x100
    return 0x8


# Simos12 Flash Info

# block sizes for S12
block_lengths_s12 = {
    1: 0x1FE00,  # CBOOT
    2: 0xBFC00,  # ASW1
    3: 0xBFC00,  # ASW2
    4: 0xBFC00,  # ASW3
    5: 0x6FC00,  # CAL
    6: 0x1FE00,  # CBOOT_temp
}

# The base address of each block on simos12

base_addresses_s12 = {
    0: 0x80000000,  # SBOOT
    1: 0x80020000,  # CBOOT
    2: 0x800C0000,  # ASW1
    3: 0x80180000,  # ASW2
    4: 0x80240000,  # ASW3
    5: 0xA0040000,  # CAL
    6: 0x80080000,  # CBOOT_temp
}

s12_binfile_offsets = {
    0: 0x0,  # SBOOT
    1: 0x20000,  # CBOOT
    2: 0xC0000,  # ASW1
    3: 0x180000,  # ASW2
    4: 0x240000,  # ASW3
    5: 0x40000,  # CAL
}

s12_iv = bytes.fromhex("306e37426b6b536f316d4a6974366d34")
s12_key = bytes.fromhex("314d7536416e3047396a413252356f45")

s12_sa2_script = bytes.fromhex(
    "6803814A10680393290720094A05872212195482499309011953824A058730032009824A0181494C"
)

s12_binfile_size = 4194304

block_names_frf_s12 = {1: "FD_0", 2: "FD_1", 3: "FD_2", 4: "FD_3", 5: "FD_4", 10: "CUS"}

s12_project_name = "SC1"

s12_crypto = aes.AES(s12_key, s12_iv)

s12_patch_info = PatchInfo(
    patch_box_code="8V0906259__0006",
    patch_block_index=3,
    patch_filename=internal_path("docs", "patch12.bin"),
    block_transfer_sizes_patch=s12_block_transfer_sizes_patch,
)

s12_flash_info = FlashInfo(
    base_addresses_s12,
    block_lengths_s12,
    s12_sa2_script,
    block_names_frf_s12,
    block_identifiers_simos,
    block_checksums_simos,
    ecu_control_module_identifier,
    software_version_location_simos,
    box_code_location_simos,
    block_transfer_sizes_simos,
    s12_binfile_offsets,
    s12_binfile_size,
    s12_project_name,
    s12_crypto,
    block_name_to_int,
    s12_patch_info,
    checksum_block_location,
)
