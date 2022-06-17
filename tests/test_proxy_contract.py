import hashlib
import secrets
import sys

import pytest
from eth_utils import to_tuple, keccak
from py_ecc.fields import FQ
from py_ecc.bls.g2_primatives import pubkey_to_G1, signature_to_G2
from py_ecc.bls.hash import expand_message_xmd
from py_ecc.bls.hash_to_curve import (
    clear_cofactor_G2,
    hash_to_field_FQ2,
    hash_to_G2,
    map_to_curve_G2,
)
from py_ecc.bls import G2ProofOfPossession
from py_ecc.optimized_bls12_381 import FQ2, normalize

EMPTY_DEPOSIT_ROOT = "d70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e"
UINT_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

def test_compute_signing_root_matches_spec(
    proxy_contract, bls_public_key, withdrawal_credentials, deposit_amount, signing_root
):
    print(signing_root)
    print(signing_root, file=sys.stderr)
    print(len(signing_root), file=sys.stdout)
    amount_in_wei = deposit_amount * 10 ** 9
    computed_signing_root = proxy_contract.functions.computeSigningRoot(
        bls_public_key, withdrawal_credentials, amount_in_wei
    ).call()
    # print(message, file=sys.stdout)
    print(len(computed_signing_root), file=sys.stdout)

    assert computed_signing_root == signing_root


def test_expand_message_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.expandMessage(signing_root).call()

    spec_result = expand_message_xmd(signing_root, dst, 256, hashlib.sha256)

    assert result == spec_result


def _convert_int_to_fp_repr(field_element):
    element_as_bytes = int(field_element).to_bytes(48, byteorder="big")
    a_bytes = element_as_bytes[:16]
    b_bytes = element_as_bytes[16:]
    return (
        int.from_bytes(a_bytes, byteorder="big"),
        int.from_bytes(b_bytes, byteorder="big"),
    )


@to_tuple
def _convert_int_to_fp2_repr(field_element):
    for coeff in field_element.coeffs:
        yield _convert_int_to_fp_repr(coeff)


def _convert_fp_to_int(fp_repr):
    a, b = fp_repr
    a_bytes = a.to_bytes(17, byteorder="big")
    b_bytes = b.to_bytes(32, byteorder="big")
    full_bytes = b"".join((a_bytes, b_bytes))
    return int.from_bytes(full_bytes, byteorder="big")


def _convert_fp2_to_int(fp2_repr):
    a, b = fp2_repr
    return FQ2((_convert_fp_to_int(a), _convert_fp_to_int(b)))


def test_hash_to_field_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToField(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = hash_to_field_FQ2(signing_root, 2, dst, hashlib.sha256)

    assert converted_result == spec_result

# def test_lmul(proxy_contract, signing_root):
#     result = proxy_contract.functions.hashToField(signing_root).call()
#     print(result)
#
#     fp_a, fp_b = result[0]
#     expected = fp_a * fp_b
#     print(f"expected: {expected}")
#
#     aa, ab = fp_a
#
#     ba, bb = fp_b
#     print(f"fpa: {fp_a}")
#     print(f"fpb: {fp_b}")
#     actual = proxy_contract.functions.lmul(aa, ab, ba, bb).call()
#
#     print(f"actual: {actual}")
#     # print(f"actual: {_convert_fp_to_int(actual)}")
#
#     # print(converted_result)
#
#     assert expected == actual
def test_base_field(proxy_contract):
    expected = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    actual = proxy_contract.functions.get_base_field().call()
    print(f"actual: {actual}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)


@pytest.mark.skip(reason="no way of currently testing this")
def test_ladd_big(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(100), FQ(FQ.field_modulus-1)
    actual = FQ(fp_a + fp_b)
    expected = FQ(99)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    assert expected == actual
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_shl_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, n = FQ(1), 10
    expected = FQ(1 << n)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.shl(fp_a_repr, n).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(expected)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_shl_medium(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, n = FQ(UINT_MAX), 10
    expected = FQ(UINT_MAX << n)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.shl(fp_a_repr, n).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(expected)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)
def test_lmul_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(3), FQ(3)
    expected = FQ(9)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(3)
    expected = FQ(UINT_MAX * 3)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)
def test_lmul_big(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(0xf12387)
    expected = FQ(UINT_MAX * 0xf12387)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_ladd_medium(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(UINT_MAX)
    expected = FQ(UINT_MAX * 2)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_ladd_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(2)
    expected = FQ(3)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_lsub_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(2), FQ(1)
    expected = FQ(1)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)
def test_lsub_medium(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 2), FQ(UINT_MAX)
    expected = FQ(UINT_MAX)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

    assert expected == _convert_fp_to_int(actual)

def test_lsub_big(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(FQ.field_modulus-1), FQ(100)
    expected = FQ(FQ.field_modulus - 101)
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    # aa, ab = fp_a
    # ba, bb = fp_b
    print(f"fpa: {fp_a}")
    print(f"typeof fpa: {type(fp_a)}")
    print(f"fpb: {fp_b}")
    print(f"typeof fpa: {type(fp_b)}")
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {type(actual)}")

def test_add():
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(2)
    expected = FQ(3)
    actual = fp_a + fp_b
    print(f"expected: {expected}")
    print(f"expected: {type(expected)}")

    assert expected == actual

def test_map_to_curve_matches_spec(proxy_contract, signing_root):
    field_elements_parts = proxy_contract.functions.hashToField(signing_root).call()
    field_elements = tuple(
        _convert_fp2_to_int(fp2_repr) for fp2_repr in field_elements_parts
    )

    # NOTE: mapToCurve (called below) precompile includes "clearing the cofactor"
    first_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[0]))
    )

    computed_first_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[0]
    ).call()
    computed_first_group_element = tuple(
        _convert_fp2_to_int(fp2_repr) for fp2_repr in computed_first_group_element_parts
    )
    assert computed_first_group_element == first_group_element

    second_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[1]))
    )

    computed_second_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[1]
    ).call()
    computed_second_group_element = tuple(
        _convert_fp2_to_int(fp2_repr)
        for fp2_repr in computed_second_group_element_parts
    )
    assert computed_second_group_element == second_group_element

# def test_add(proxy_contract, signing_root, dst):
#     P1 = proxy_contract.functions.hashToCurve(signing_root).call()
#     converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)
#
#     spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
#
#     assert converted_result == spec_result

def test_hash_g2_is_zero(proxy_contract, signing_root, dst):
    
    result = proxy_contract.functions.hashToCurve(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))

    assert converted_result == spec_result

def test_hash_to_curve_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurve(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))

    assert converted_result == spec_result

def test_hash_to_curve_no_precompile_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurveNoPrecompile(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    print(f"expected: {converted_result}")
    print(f"actual: {spec_result}")
    assert converted_result == spec_result

def test_bls_pairing_check(proxy_contract, signing_root, bls_public_key, signature):
    public_key_point = pubkey_to_G1(bls_public_key)
    public_key = normalize(public_key_point)
    public_key_repr = (
        _convert_int_to_fp_repr(public_key[0]),
        _convert_int_to_fp_repr(public_key[1]),
    )

    # skip some data wrangling by calling contract function for this...
    message_on_curve = proxy_contract.functions.hashToCurve(signing_root).call()

    projective_signature_point = signature_to_G2(signature)
    signature_point = normalize(projective_signature_point)
    signature_repr = (
        _convert_int_to_fp2_repr(signature_point[0]),
        _convert_int_to_fp2_repr(signature_point[1]),
    )
    assert proxy_contract.functions.blsPairingCheck(
        public_key_repr, message_on_curve, signature_repr
    ).call()


def test_bls_signature_is_valid_works_with_valid_signature(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_message(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    message = b"\x01" + signing_root[1:]
    assert message != signing_root

    assert not proxy_contract.functions.blsSignatureIsValid(
        message,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_public_key(
    proxy_contract, seed, signing_root, signature, signature_witness
):
    another_seed = "another-secret".encode()
    assert seed != another_seed
    another_private_key = G2ProofOfPossession.KeyGen(another_seed)
    public_key = G2ProofOfPossession.SkToPk(another_private_key)

    group_element = pubkey_to_G1(public_key)
    normalized_group_element = normalize(group_element)
    public_key_witness = normalized_group_element[1]
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


def test_bls_signature_is_valid_fails_with_invalid_signature(
    proxy_contract, bls_public_key, signing_root, public_key_witness, bls_private_key
):
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    another_message = hashlib.sha256(b"not the signing root").digest()
    assert signing_root != another_message
    signature = G2ProofOfPossession.Sign(bls_private_key, another_message)
    group_element = signature_to_G2(signature)
    normalized_group_element = normalize(group_element)
    signature_witness = normalized_group_element[1]

    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()
