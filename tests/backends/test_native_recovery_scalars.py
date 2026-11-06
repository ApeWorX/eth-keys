import pytest

from eth_keys.backends import CoinCurveECCBackend, NativeECCBackend
from eth_keys.backends.native.ecdsa import ecdsa_raw_recover
from eth_keys.constants import SECPK1_G, SECPK1_N
from eth_keys.datatypes import PrivateKey
from eth_keys.exceptions import BadSignature


@pytest.mark.parametrize("z", [0, 1, SECPK1_N - 1, SECPK1_N, SECPK1_N + 1])
def test_recovery_matches_coincurve_at_message_boundaries(z):
    message_hash = z.to_bytes(32, "big")
    key_bytes = (SECPK1_N - 1).to_bytes(32, "big")
    native_key = PrivateKey(key_bytes, backend=NativeECCBackend())
    curve_key = PrivateKey(key_bytes, backend=CoinCurveECCBackend())
    native_sig = native_key.sign_msg_hash(message_hash)
    curve_sig = curve_key.sign_msg_hash(message_hash)
    assert native_sig.recover_public_key_from_msg_hash(message_hash) == (
        curve_sig.recover_public_key_from_msg_hash(message_hash)
    )


def test_recovery_rejects_identity_result():
    # r = Gx, s = 1, z = 1 makes s*R - z*G the point at infinity.
    with pytest.raises(BadSignature, match="^InvalidSignature$"):
        ecdsa_raw_recover((1).to_bytes(32, "big"), (SECPK1_G[1] % 2, SECPK1_G[0], 1))
