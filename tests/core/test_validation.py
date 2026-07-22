import pytest
from eth_utils import (
    ValidationError,
)

from eth_keys.constants import (
    SECPK1_N,
)
from eth_keys.validation import (
    validate_private_key_bytes,
)


def _to_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


@pytest.mark.parametrize(
    "value",
    (
        _to_bytes(0),  # zero is not a valid private key
        _to_bytes(SECPK1_N),  # equal to the curve order
        _to_bytes(SECPK1_N + 1),  # greater than the curve order
    ),
)
def test_validate_private_key_bytes_rejects_out_of_range(value):
    with pytest.raises(ValidationError):
        validate_private_key_bytes(value)


@pytest.mark.parametrize(
    "value",
    (
        _to_bytes(1),  # smallest valid private key
        _to_bytes(SECPK1_N - 1),  # largest valid private key
    ),
)
def test_validate_private_key_bytes_accepts_in_range(value):
    validate_private_key_bytes(value)
