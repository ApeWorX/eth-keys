import pytest

from eth_keys.backends.native.jacobian import inv
from eth_keys.constants import SECPK1_N, SECPK1_P


@pytest.mark.parametrize("modulus", [SECPK1_P, SECPK1_N])
def test_inverse_prime_boundaries(modulus):
    assert inv(0, modulus) == 0
    # Preserve the old extended-Euclidean result for these noninvertible inputs.
    assert inv(modulus, modulus) == 1
    assert inv(-modulus, modulus) == 1
    for value in [1, -1, modulus - 1, modulus + 1, 2**512 + 9]:
        assert inv(value, modulus) * value % modulus == 1


def test_inverse_preserves_general_modulus_behavior():
    assert inv(2, 4) == 2
    assert inv(6, 9) == 3
    assert inv(0, 0) == 0
