import asn1tools
import pytest
from hypothesis import (
    example,
    given,
    settings,
)
from hypothesis import (
    strategies as st,
)
from pyasn1.codec.der import (
    decoder as pyasn1_decoder,
)
from pyasn1.codec.der import (
    encoder as pyasn1_encoder,
)
from pyasn1.type import (
    namedtype,
    univ,
)

from eth_keys.utils.der import (
    two_int_sequence_decoder,
    two_int_sequence_encoder,
)

ASN1_ECDSA_SPEC_STRING = """\
ECDSASpec DEFINITIONS ::= BEGIN
      ECDSASignature ::= SEQUENCE {
         r   INTEGER,
         s   INTEGER
     }
END
"""
ASN1_SPEC = asn1tools.compile_string(ASN1_ECDSA_SPEC_STRING, "der")


def asn1tools_encode(r, s):
    return ASN1_SPEC.encode("ECDSASignature", {"r": r, "s": s})


def asn1tools_decode(encoded):
    decoded = ASN1_SPEC.decode("ECDSASignature", encoded)
    return decoded["r"], decoded["s"]


class TwoInts(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("r", univ.Integer()),
        namedtype.NamedType("s", univ.Integer()),
    )


def pyasn1_encode(r, s):
    structured = TwoInts()
    structured["r"] = r
    structured["s"] = s
    return pyasn1_encoder.encode(structured)


def pyasn1_decode(encoded):
    decoded = pyasn1_decoder.decode(encoded, asn1Spec=TwoInts())
    return decoded[0]["r"], decoded[0]["s"]


MAX_32_BYTE_INT = 256**32 - 1
uint32strategy = st.integers(min_value=0, max_value=MAX_32_BYTE_INT)


@pytest.mark.parametrize(
    "encoder, decoder",
    (
        (two_int_sequence_encoder, asn1tools_decode),
        (two_int_sequence_encoder, pyasn1_decode),
        (two_int_sequence_encoder, two_int_sequence_decoder),
        (asn1tools_encode, two_int_sequence_decoder),
        (pyasn1_encode, two_int_sequence_decoder),
    ),
    ids=(
        "local_encode=>asn1tools_decode",
        "local_encode=>pyasn1_decode",
        "local_encode=>local_decode",
        "asn1tools_encode=>local_decode",
        "pyasn1_encode=>local_decode",
    ),
)
@given(
    uint32strategy,
    uint32strategy,
)
@example(0, 0)
@example(MAX_32_BYTE_INT, MAX_32_BYTE_INT)
@example(MAX_32_BYTE_INT // 2, MAX_32_BYTE_INT // 2)
@example(MAX_32_BYTE_INT // 2 + 1, MAX_32_BYTE_INT // 2 + 1)
@settings(max_examples=500)
def test_encode_decode_pairings(encoder, decoder, r, s):
    encoded = encoder(r, s)
    end_r, end_s = decoder(encoded)
    assert (end_r, end_s) == (r, s)
