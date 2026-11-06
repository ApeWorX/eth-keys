import random

import pytest

from eth_keys.backends.native._public import (
    _A1,
    _A2,
    _B1,
    _BETA,
    _joint_multiply,
    _naf,
    _split,
)
from eth_keys.backends.native.jacobian import (
    fast_add,
    fast_multiply,
    from_jacobian,
)
from eth_keys.constants import SECPK1_G as G
from eth_keys.constants import SECPK1_N as N
from eth_keys.constants import SECPK1_P as P

_LAMBDA = 0x5363AD4CC05C30E0A5261C028812645A122E22EA20816678DF02967C1B23BD72


def test_endomorphism_and_lattice_constants():
    assert pow(_BETA, 3, P) == 1 and _BETA != 1
    assert (_LAMBDA * _LAMBDA + _LAMBDA + 1) % N == 0
    assert fast_multiply(G, _LAMBDA) == (G[0] * _BETA % P, G[1])
    assert (_A1 + _LAMBDA * _B1) % N == 0
    assert (_A2 + _LAMBDA * _A1) % N == 0
    assert _A1 * _A1 - _B1 * _A2 == N


def test_scalar_decomposition_and_signed_digits():
    rng = random.Random(702)
    for scalar in [0, 1, N - 1] + [rng.randrange(N) for _ in range(3000)]:
        first, second = _split(scalar)
        assert (first + _LAMBDA * second) % N == scalar
        assert max(abs(first).bit_length(), abs(second).bit_length()) <= 129
        for part in (first, second):
            digits = _naf(abs(part))
            assert sum(digit << bit for bit, digit in enumerate(digits)) == abs(part)
            assert all(
                digit == 0 or (digit & 1 and abs(digit) < 16) for digit in digits
            )


@pytest.mark.parametrize("point", [G, (G[0], P - G[1]), fast_multiply(G, 17)])
def test_joint_multiplication_boundaries_and_cancellation(point):
    for first in [0, 1, 2, N - 1]:
        for second in [0, 1, 2, N - 1]:
            assert from_jacobian(_joint_multiply(first, point, second)) == fast_add(
                fast_multiply(G, first), fast_multiply(point, second)
            )


def test_signed_naf_window_widths():
    for width in [4, 5, 10]:
        for scalar in [-N, -129, -128, -1, 0, 1, 128, 129, N]:
            digits = _naf(scalar, width)
            assert sum(digit << bit for bit, digit in enumerate(digits)) == scalar
            assert all(abs(digit) < 1 << (width - 1) for digit in digits)
