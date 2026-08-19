import pytest
from eth_utils import (
    int_to_big_endian,
    keccak,
)
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import (
    strategies as st,
)
from strategies import (
    message_hash_st,
    private_key_st,
    signature_st,
)

from eth_keys import (
    KeyAPI,
)
from eth_keys.backends import (
    CoinCurveECCBackend,
    NativeECCBackend,
)
from eth_keys.constants import (
    SECPK1_N,
)
from eth_keys.exceptions import (
    BadSignature,
)
from eth_keys.utils.padding import (
    pad32,
)

MSG = b"message"
MSGHASH = keccak(MSG)

MAX_EXAMPLES = 200


@pytest.fixture(scope="module")
def native_key_api():
    return KeyAPI(backend=NativeECCBackend())


@pytest.fixture(scope="module")
def coincurve_key_api():
    return KeyAPI(backend=CoinCurveECCBackend())


@given(
    private_key_bytes=private_key_st,
)
@settings(max_examples=MAX_EXAMPLES)
def test_public_key_generation_is_equal(
    private_key_bytes, native_key_api, coincurve_key_api
):
    native_public_key = native_key_api.PrivateKey(private_key_bytes).public_key
    coincurve_public_key = coincurve_key_api.PrivateKey(private_key_bytes).public_key

    assert native_public_key == coincurve_public_key


@given(
    private_key_bytes=private_key_st,
    message_hash=message_hash_st,
)
@example(
    private_key_bytes=pad32(int_to_big_endian(1)),
    message_hash=int_to_big_endian(SECPK1_N),
)
@settings(max_examples=MAX_EXAMPLES)
def test_signing_is_equal(
    private_key_bytes, message_hash, native_key_api, coincurve_key_api
):
    native_private_key = native_key_api.PrivateKey(private_key_bytes)
    native_signature = native_key_api.ecdsa_sign(message_hash, native_private_key)
    native_non_recoverable_signature = native_key_api.ecdsa_sign_non_recoverable(
        message_hash,
        native_private_key,
    )

    coincurve_private_key = coincurve_key_api.PrivateKey(private_key_bytes)
    coincurve_signature = coincurve_key_api.ecdsa_sign(
        message_hash, coincurve_private_key
    )
    coincurve_non_recoverable_signature = coincurve_key_api.ecdsa_sign_non_recoverable(
        message_hash,
        coincurve_private_key,
    )

    assert native_signature == coincurve_signature
    assert native_non_recoverable_signature == coincurve_non_recoverable_signature


@given(
    private_key_bytes=private_key_st,
    message_hash=message_hash_st,
    direction=st.one_of(
        st.just("coincurve-to-native"),
        st.just("native-to-coincurve"),
    ),
)
@settings(max_examples=MAX_EXAMPLES)
def test_native_to_coincurve_recover(
    private_key_bytes, message_hash, direction, native_key_api, coincurve_key_api
):
    if direction == "coincurve-to-native":
        backend_a = coincurve_key_api
        backend_b = native_key_api
    elif direction == "native-to-coincurve":
        backend_b = coincurve_key_api
        backend_a = native_key_api
    else:
        raise AssertionError("invariant")

    private_key_a = backend_a.PrivateKey(private_key_bytes)
    public_key_a = private_key_a.public_key
    signature_a = backend_a.ecdsa_sign(message_hash, private_key_a)

    public_key_b = backend_b.ecdsa_recover(message_hash, signature_a)
    assert public_key_b == public_key_a
    assert backend_b.ecdsa_verify(message_hash, signature_a, public_key_b)


@given(
    message_hash=message_hash_st,
    signature_bytes=signature_st,
    direction=st.one_of(
        st.just("coincurve-to-native"),
        st.just("native-to-coincurve"),
    ),
)
@settings(max_examples=MAX_EXAMPLES)
def test_coincurve_to_native_invalid_signatures(
    message_hash, signature_bytes, direction, native_key_api, coincurve_key_api
):
    if direction == "coincurve-to-native":
        backend_a = coincurve_key_api
        backend_b = native_key_api
    elif direction == "native-to-coincurve":
        backend_b = coincurve_key_api
        backend_a = native_key_api
    else:
        raise AssertionError("invariant")

    try:
        signature_a = backend_a.Signature(signature_bytes)
    except BadSignature:
        is_bad_signature = True
    else:
        is_bad_signature = False

    if is_bad_signature:
        with pytest.raises(BadSignature):
            backend_b.Signature(signature_bytes)
        return
    try:
        public_key_a = backend_a.ecdsa_recover(message_hash, signature_a)
    except BadSignature:
        is_bad_recovery = True
    else:
        is_bad_recovery = False

    if is_bad_recovery:
        with pytest.raises(BadSignature):
            backend_b.ecdsa_recover(message_hash, signature_a)
        return

    public_key_b = backend_b.ecdsa_recover(message_hash, signature_a)

    assert public_key_b == public_key_a


@given(
    private_key_bytes=private_key_st,
)
def test_public_key_compression_is_equal(
    private_key_bytes, native_key_api, coincurve_key_api
):
    native_public_key = native_key_api.PrivateKey(private_key_bytes).public_key
    coincurve_public_key = coincurve_key_api.PrivateKey(private_key_bytes).public_key

    native_compressed_public_key = native_public_key.to_compressed_bytes()
    coincurve_compressed_public_key = coincurve_public_key.to_compressed_bytes()

    assert native_compressed_public_key == coincurve_compressed_public_key


@given(
    private_key_bytes=private_key_st,
)
def test_public_key_decompression_is_equal(
    private_key_bytes, native_key_api, coincurve_key_api
):
    public_key_template = coincurve_key_api.PrivateKey(private_key_bytes).public_key
    compressed_public_key = public_key_template.to_compressed_bytes()

    native_public_key = native_key_api.PublicKey.from_compressed_bytes(
        compressed_public_key
    )
    coincurve_public_key = coincurve_key_api.PublicKey.from_compressed_bytes(
        compressed_public_key
    )

    assert native_public_key == coincurve_public_key
