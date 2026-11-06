import pytest
from eth_utils import int_to_big_endian

from eth_keys.backends import CoinCurveECCBackend
from eth_keys.backends.native.jacobian import (
    _generator_windows,
    fast_multiply,
    from_jacobian,
    jacobian_multiply,
    to_jacobian,
)
from eth_keys.constants import SECPK1_G, SECPK1_N
from eth_keys.datatypes import PrivateKey
from eth_keys.utils.padding import pad32


@pytest.mark.parametrize(
    "scalar",
    [0, 1, 2, 3, 31, 32, 33, 63, 64, 255, 256, 257, SECPK1_N - 1, SECPK1_N]
    + [SECPK1_N + 1, -1, 2**255, 2**256 - 1],
)
def test_fixed_generator_matches_generic_multiplication(scalar):
    assert fast_multiply(SECPK1_G, scalar) == from_jacobian(
        jacobian_multiply(to_jacobian(SECPK1_G), scalar)
    )


def test_generator_windows_match_coincurve():
    table = _generator_windows()
    assert len(table) == 43
    for window, packed in enumerate(table):
        for digit in range(1, 33):
            x = packed & ((1 << 256) - 1)
            y = (packed >> 256) & ((1 << 256) - 1)
            packed >>= 512
            scalar = (digit << (6 * window)) % SECPK1_N
            key = PrivateKey(
                pad32(int_to_big_endian(scalar)), backend=CoinCurveECCBackend()
            )
            assert (
                x.to_bytes(32, "big") + y.to_bytes(32, "big")
                == key.public_key.to_bytes()
            )
    assert _generator_windows.cache_info().currsize == 1
