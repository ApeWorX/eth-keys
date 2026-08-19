from eth_keys.constants import (
    SECPK1_N,
)


def int_to_byte(value: int) -> bytes:
    return bytes([value])


def coerce_low_s(value: int) -> int:
    """
    Coerce the s component of an ECDSA signature into its low-s form.

    See the Bitcoin Stack Exchange discussion about complementary ECDSA
    signatures, or https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2.md.
    """  # blocklint:  pragma
    return min(value, -value % SECPK1_N)
