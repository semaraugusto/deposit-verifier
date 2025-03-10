import hashlib
import sys
from typing import (
    Optional,
    Tuple,
    TypeVar,
    Union,
)
from py_ecc.typing import (
    Optimized_Field,
    Optimized_Point3D,
)

import pytest
from eth_utils import to_tuple, keccak
# from py_ecc.fields import FQ, FQ2
from py_ecc.fields import (
    bls12_381_FQ as FQ,
    bls12_381_FQ2 as FQ2,
)
from py_ecc.typing import (
    Field,
    GeneralPoint,
    Point2D,
    # FQ2,
)
from py_ecc.bls.g2_primatives import pubkey_to_G1, signature_to_G2
from py_ecc.bls.hash import expand_message_xmd
from py_ecc.bls.hash_to_curve import (
    clear_cofactor_G2,
    hash_to_field_FQ2,
    hash_to_G2,
    map_to_curve_G2,
)
# from py_ecc.bls12_381 import add
from py_ecc.bls import G2ProofOfPossession
from py_ecc.optimized_bls12_381 import FQ2, normalize, addTest
# from utils import utils.convert_int_to_fp_repr, convert_int_to_fp2_repr, convert_big_to_int, convert_fp_to_int, convert_fp2_to_int, convert_big_to_fp_repr
import utils
import py_ecc

EMPTY_DEPOSIT_ROOT = "d70a234731285c6804c2a4f56711ddb8c82c99740f207854891028af34e27e5e"
UINT_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
UINT_64_MAX = 18446744073709551615
UINT_32_MAX = 18446744073709551615

# Field = TypeVar(
#     'Field',
#     # General
#     FQ,
#     FQ2,
#     py_ecc.fields.bls12_381_FQ2
# )

def test_compute_signing_root_matches_spec(
    proxy_contract, bls_public_key, withdrawal_credentials, deposit_amount, signing_root, deposit_domain
):
    amount_in_wei = deposit_amount * 10 ** 9
    computed_signing_root = proxy_contract.functions.computeSigningRoot(
        bls_public_key, withdrawal_credentials, amount_in_wei
    ).call()
    print(signing_root, file=sys.stderr)
    print(computed_signing_root)
    assert computed_signing_root == signing_root


def test_expand_message_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.expandMessage(signing_root).call()

    spec_result = expand_message_xmd(signing_root, dst, 256, hashlib.sha256)

    assert result == spec_result

def test_hash_to_field_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToField(signing_root).call()
    utils.converted_result = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = hash_to_field_FQ2(signing_root, 2, dst, hashlib.sha256)

    assert utils.converted_result == spec_result

def test_ladd_fq2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ2([FQ(1), FQ(1)]), FQ2([FQ(2), FQ(2)])
    expected = (FQ(3), FQ(3))
    fp_a_repr = utils.convert_int_to_fp2_repr(fp_a)
    fp_b_repr = utils.convert_int_to_fp2_repr(fp_b)
    actual = proxy_contract.functions.ladd(fp_a_repr, fp_b_repr).call({'gas': 1000000000})
    actual = tuple(utils.convert_fp_to_int(fp2_repr) for fp2_repr in actual)
    print(f"actual: {utils.convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == actual

@pytest.mark.skip(reason="no way of currently testing this")
def test_lsub_0(proxy_contract, fplib_contract, signing_root):
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    first_g2 = points[0]
    second_g2 = points[1]
    first_g2_pyecc =[]
    for tup in first_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        first_g2_pyecc.append(p);
    
    first_g2_pyecc.append(FQ2.one());
    first_g2_pyecc = tuple(first_g2_pyecc)

    second_g2_pyecc =[]
    for tup in second_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        second_g2_pyecc.append(p);
    
    second_g2_pyecc.append(FQ2.one());
    second_g2_pyecc = tuple(second_g2_pyecc)
    result, u1, u2 = addTest(first_g2_pyecc,second_g2_pyecc)
    expected = u1 - u2

    u1a, _ = u1.coeffs
    u2a, _ = u2.coeffs
    u1a = utils.convert_int_to_fp_repr(u1a)
    u2a = utils.convert_int_to_fp_repr(u2a)
    actual = fplib_contract.functions.lsub(u1a, u2a).call()
    actual = utils.convert_fp_to_int(actual)
    print(f"{actual=}")
    print(f"{expected=}")
    assert expected.coeffs[0] == actual

@pytest.mark.skip(reason="no way of currently testing this")
def test_lsub_1(proxy_contract, fplib_contract, signing_root):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    FIELD_MODULUS = FQ(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    first_g2 = points[0]
    second_g2 = points[1]
    first_g2_pyecc =[]
    for tup in first_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        first_g2_pyecc.append(p);
    
    first_g2_pyecc.append(FQ2.one());
    first_g2_pyecc = tuple(first_g2_pyecc)

    second_g2_pyecc =[]
    for tup in second_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        second_g2_pyecc.append(p);
    
    second_g2_pyecc.append(FQ2.one());
    second_g2_pyecc = tuple(second_g2_pyecc)
    result, u1, u2 = addTest(first_g2_pyecc,second_g2_pyecc)
    expected = u1 - u2

    _, x = u1.coeffs
    _, y = u2.coeffs
    x_repr = utils.convert_int_to_fp_repr(x)
    y_repr = utils.convert_int_to_fp_repr(y)
    actual_repr = fplib_contract.functions.lsub(x_repr, y_repr).call()
    print(f"{x_repr = }")
    print(f"{y_repr = }")
    print(f"{actual_repr = }")
    print(f"expected_repr{utils.convert_int_to_fp_repr(expected.coeffs[1]) = }")
    actual = utils.convert_big_to_int(actual_repr)
    print(f"{FIELD_MODULUS=}")
    print(f"{x = }")
    print(f"{y = }")
    print(f"  {actual = }")
    print(f"expected = {expected.coeffs[1]}")
    assert expected.coeffs[1] == actual

@pytest.mark.skip(reason="no way of currently testing this")
def test_lsub(proxy_contract, fplib_contract, signing_root):
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    first_g2 = points[0]
    second_g2 = points[1]
    first_g2_pyecc =[]
    for tup in first_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        first_g2_pyecc.append(p);
    
    first_g2_pyecc.append(FQ2.one());
    first_g2_pyecc = tuple(first_g2_pyecc)

    second_g2_pyecc =[]
    for tup in second_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        second_g2_pyecc.append(p);
    
    second_g2_pyecc.append(FQ2.one());
    second_g2_pyecc = tuple(second_g2_pyecc)
    result, u1, u2 = addTest(first_g2_pyecc,second_g2_pyecc)
    expected = u1 - u2

    u1a, u1b = u1.coeffs
    u2a, u2b = u2.coeffs
    u1a = utils.convert_int_to_fp_repr(u1a)
    u1b = utils.convert_int_to_fp_repr(u1b)
    u2a = utils.convert_int_to_fp_repr(u2a)
    u2b = utils.convert_int_to_fp_repr(u2b)
    u1 = (u1a, u1b)
    u2 = (u2a, u2b)
    actual = proxy_contract.functions.lsub(u1, u2).call()
    actual = FQ2([utils.convert_fp_to_int(a) for a in actual])
    print(f"{actual=}")
    print(f"{expected=}")
    assert expected == actual

# @pytest.mark.skip(reason="no way of currently testing this")
def test_ladd_G2_1(proxy_contract, signing_root):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    FIELD_MODULUS = FQ(0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab)
    expected1 = proxy_contract.functions.hashToCurve(signing_root).call()
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    expected = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    # spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # expected1 = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    first_g2 = points[0]
    second_g2 = points[1]
    # first_g2_ecc = [FQ2([) for tup in first_g2]
    first_g2_pyecc =[]
    for tup in first_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        first_g2_pyecc.append(p);
    
    first_g2_pyecc.append(FQ2.one());
    first_g2_pyecc = tuple(first_g2_pyecc)

    second_g2_pyecc =[]
    for tup in second_g2:
        p = []
        for f in tup:
            p.append(FQ(utils.convert_fp_to_int(f)))

        p = FQ2(p)
        second_g2_pyecc.append(p);
    
    second_g2_pyecc.append(FQ2.one());
    second_g2_pyecc = tuple(second_g2_pyecc)
    result, v, v_sqr = addTest(first_g2_pyecc,second_g2_pyecc)
    first_g2_pyecc = tuple(first_g2_pyecc)
    exp1 = proxy_contract.functions.addG2(first_g2, second_g2).call()
    actual1 = proxy_contract.functions.addG2NoPrecompile(first_g2, second_g2).call()
    exp = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in exp1)
    actual = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in actual1)
    print(f"modulus: {FIELD_MODULUS}")
    print(f"IN_V: {actual[1]}")
    print(f"HERE: {actual[2]}")
    print(f"v: {v}")
    print(f"v_sqr: {v_sqr}")
    assert v_sqr == actual[2]
    result = normalize(result)
    actual = normalize(actual)

    assert exp == expected
    assert result == expected
    assert actual == expected

def test_map_to_curve_matches_spec(proxy_contract, signing_root):
    field_elements_parts = proxy_contract.functions.hashToField(signing_root).call()
    field_elements = tuple(
        utils.convert_fp2_to_int(fp2_repr) for fp2_repr in field_elements_parts
    )

    # NOTE: mapToCurve (called below) precompile includes "clearing the cofactor"
    first_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[0]))
    )

    computed_first_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[0]
    ).call()
    computed_first_group_element = tuple(
        utils.convert_fp2_to_int(fp2_repr) for fp2_repr in computed_first_group_element_parts
    )
    assert computed_first_group_element == first_group_element

    second_group_element = normalize(
        clear_cofactor_G2(map_to_curve_G2(field_elements[1]))
    )

    computed_second_group_element_parts = proxy_contract.functions.mapToCurve(
        field_elements_parts[1]
    ).call()
    computed_second_group_element = tuple(
        utils.convert_fp2_to_int(fp2_repr)
        for fp2_repr in computed_second_group_element_parts
    )
    assert computed_second_group_element == second_group_element

def test_hash_g2_is_zero(proxy_contract, signing_root, dst):
    
    result = proxy_contract.functions.hashToCurve(signing_root).call()
    utils.converted_result = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))

    assert utils.converted_result == spec_result

def test_hash_to_curve_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurve(signing_root).call()
    utils.converted_result = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in result)

    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))

    assert utils.converted_result == spec_result

@pytest.mark.skip(reason="no way of currently testing this")
def test_hash_to_curve_no_precompile_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurveNoPrecompile(signing_root).call()
    expected1 = proxy_contract.functions.hashToCurve(signing_root).call()
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    utils.converted_expected = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    utils.converted_result = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # utils.converted_result = tuple(convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    # expected1 = tuple(utils.convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    first_g2 = points[0]
    second_g2 = points[1]
    print(f"expected: {utils.converted_expected}")
    print(f"actual: {spec_result}")
    # print(f"first_point: {first_point}")
    first_g2_a = first_g2[0]
    first_g2_a_a = first_g2_a[0]
    first_g2_a_b = first_g2_a[1]
    first_g2_b = first_g2[1]
    first_g2_b_a = first_g2_b[0]
    first_g2_b_b = first_g2_b[1]
    second_g2_a = second_g2[0]
    second_g2_a_a = second_g2_a[0]
    second_g2_a_b = second_g2_a[1]
    second_g2_b = second_g2[1]
    second_g2_b_a = second_g2_b[0]
    second_g2_b_b = second_g2_b[1]
    print(f"first_point_g2_a_a: {first_g2_a_a}")
    print(f"first_point_g2_a_b: {first_g2_a_b}")
    print(f"first_point_g2_b_a: {first_g2_b_a}")
    print(f"first_point_g2_b_b: {first_g2_b_b}")

    print(f"second_point_g2_a_a: {second_g2_a_a}")
    print(f"second_point_g2_a_b: {second_g2_a_b}")
    print(f"second_point_g2_b_a: {second_g2_b_a}")
    print(f"second_point_g2_b_b: {second_g2_b_b}")

    # print(f"second_point: {second_point}")
    assert utils.converted_expected == spec_result
    assert utils.converted_result == spec_result

@pytest.mark.skip(reason="no way of currently testing this")
def test_hash_to_curve_no_precompile_matches_spec_2(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurveNoPrecompile(signing_root).call()
    expected = proxy_contract.functions.hashToCurve(signing_root).call()
    utils.converted_result = tuple(convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    # spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # print(f"expected: {utils.converted_result}")
    # print(f"actual: {spec_result}")
    assert expected == result


@pytest.mark.skip(reason="function was commented out due to gas issues")
def test_bls_pairing_check(proxy_contract, signing_root, bls_public_key, signature):
    public_key_point = pubkey_to_G1(bls_public_key)
    public_key = normalize(public_key_point)
    public_key_repr = (
        utils.convert_int_to_fp_repr(public_key[0]),
        utils.convert_int_to_fp_repr(public_key[1]),
    )

    # skip some data wrangling by calling contract function for this...
    message_on_curve = proxy_contract.functions.hashToCurve(signing_root).call()

    projective_signature_point = signature_to_G2(signature)
    signature_point = normalize(projective_signature_point)
    signature_repr = (
        utils.convert_int_to_fp2_repr(signature_point[0]),
        utils.convert_int_to_fp2_repr(signature_point[1]),
    )
    assert proxy_contract.functions.blsPairingCheck(
        public_key_repr, message_on_curve, signature_repr
    ).call()


@pytest.mark.skip(reason="function was commented out due to gas issues")
def test_bls_signature_is_valid_works_with_valid_signature(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = utils.convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = utils.convert_int_to_fp2_repr(signature_witness)

    assert proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


@pytest.mark.skip(reason="function was commented out due to gas issues")
def test_bls_signature_is_valid_fails_with_invalid_message(
    proxy_contract,
    bls_public_key,
    signing_root,
    signature,
    public_key_witness,
    signature_witness,
):
    public_key_witness_repr = utils.convert_int_to_fp_repr(public_key_witness)
    signature_witness_repr = utils.convert_int_to_fp2_repr(signature_witness)

    message = b"\x01" + signing_root[1:]
    assert message != signing_root

    assert not proxy_contract.functions.blsSignatureIsValid(
        message,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


@pytest.mark.skip(reason="function was commented out due to gas issues")
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
    public_key_witness_repr = utils.convert_int_to_fp_repr(public_key_witness)

    signature_witness_repr = utils.convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()


@pytest.mark.skip(reason="function was commented out due to gas issues")
def test_bls_signature_is_valid_fails_with_invalid_signature(
    proxy_contract, bls_public_key, signing_root, public_key_witness, bls_private_key
):
    public_key_witness_repr = utils.convert_int_to_fp_repr(public_key_witness)

    another_message = hashlib.sha256(b"not the signing root").digest()
    assert signing_root != another_message
    signature = G2ProofOfPossession.Sign(bls_private_key, another_message)
    group_element = signature_to_G2(signature)
    normalized_group_element = normalize(group_element)
    signature_witness = normalized_group_element[1]

    signature_witness_repr = utils.convert_int_to_fp2_repr(signature_witness)

    assert not proxy_contract.functions.blsSignatureIsValid(
        signing_root,
        bls_public_key,
        signature,
        public_key_witness_repr,
        signature_witness_repr,
    ).call()
