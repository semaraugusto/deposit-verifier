import hashlib
import secrets
import sys

import pytest
from eth_utils import to_tuple, keccak
from py_ecc.fields import FQ, FQ2
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
UINT_64_MAX = 18446744073709551615
UINT_32_MAX = 18446744073709551615

def test_compute_signing_root_matches_spec(
    proxy_contract, bls_public_key, withdrawal_credentials, deposit_amount, signing_root, deposit_domain
):
    # print(signing_root)
    # print(signing_root, file=sys.stderr)
    # print(len(signing_root), file=sys.stdout)
    amount_in_wei = deposit_amount * 10 ** 9
    computed_signing_root = proxy_contract.functions.computeSigningRoot(
        bls_public_key, withdrawal_credentials, amount_in_wei
    ).call()
    # print(message, file=sys.stdout)
    # print(signing_root)
    print(signing_root, file=sys.stderr)
    print(len(signing_root), file=sys.stdout)
    print(len(computed_signing_root), file=sys.stdout)
    print(computed_signing_root)
    # print(bytes(computed_signing_root)  )
    # print(bytes.fromhex(computed_signing_root)  )
    # print(bytes.fromhex(computed_signing_root)  )
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

def _convert_int_to_fp_repr(field_element):
    element_as_bytes = int(field_element).to_bytes(64, byteorder="big")
    a_bytes = element_as_bytes[:32]
    b_bytes = element_as_bytes[32:]
    return (
        int.from_bytes(a_bytes, byteorder="big"),
        int.from_bytes(b_bytes, byteorder="big"),
    )


@to_tuple
def _convert_int_to_fp2_repr(field_element):
    for coeff in field_element.coeffs:
        yield _convert_int_to_fp_repr(coeff)


def _convert_big_to_int(fp_repr):
    a, b = fp_repr
    a_bytes = a.to_bytes(32, byteorder="big")
    b_bytes = b.to_bytes(32, byteorder="big")
    full_bytes = b"".join((a_bytes, b_bytes))
    return int.from_bytes(full_bytes, byteorder="big")

def _convert_fp_to_int(fp_repr):
    a, b = fp_repr
    a_bytes = a.to_bytes(16, byteorder="big")
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

def test_base_field(fplib_contract):
    expected = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    actual = fplib_contract.functions.get_base_field().call()
    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)


def test_lgte_small_eq(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(10), FQ(10)
    expected = 1
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_small_gt(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(11), FQ(10)
    expected = 1
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_small_lt(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(9), FQ(10)
    expected = 0
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_medium_eq(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX + 1), FQ(UINT_MAX + 1)
    expected = 1
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_medium_gt(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX + 2), FQ(UINT_MAX + 1)
    expected = 1
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_medium_lt(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX + 1), FQ(UINT_MAX + 2)
    expected = 0
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_medium_gt_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(45442060874369865957053122457065728162598490762543039060009208264153100167950), FQ(UINT_MAX)
    expected = 0
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_lgte_medium_lt_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 10), FQ(UINT_MAX*10 + 2)
    expected = 0
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lgte(fp_a_repr, fp_b_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")
    assert expected == actual

def test_bit_length_big(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(FQ.field_modulus-1)
    expected = FQ(384)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = fplib_contract.functions.bitLength(fp_a_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")

def test_bit_length_medium_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(UINT_MAX*2)
    expected = FQ(257)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = fplib_contract.functions.bitLength(fp_a_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual


def test_bit_length_medium_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(UINT_MAX)
    expected = FQ(256)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.bitLength(fp_a_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual

def test_bit_length_small_2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(10)
    expected = FQ(4)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.bitLength(fp_a_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual

def test_bit_length_small_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(1)
    expected = FQ(1)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.bitLength(fp_a_repr).call()

    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual

def test_ldiv_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(10), 2
    expected = FQ(5)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ldiv(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_ldiv_medium_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 10 + 10), FQ(UINT_MAX * 10)
    expected = FQ(1)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ldiv(fp_a_repr, fp_b_repr).call()

    print(f"field_module_medium_2: actual: {_convert_fp_to_int(actual)}")
    print(f"field_module_medium_2: expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_ldiv_medium_2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 10), FQ(UINT_MAX * 10)
    expected = FQ(1)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ldiv(fp_a_repr, fp_b_repr).call()

    print(f"field_module_medium_2: actual: {_convert_fp_to_int(actual)}")
    print(f"field_module_medium_2: expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_ldiv_big(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 1_000_000_000), 1_000_000_000
    expected = FQ(UINT_MAX)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.ldiv(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_shl_small(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, n = FQ(1), 10
    expected = FQ(1 << n)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.shl(fp_a_repr, n).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_shl_medium(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, n = FQ(UINT_MAX), 10
    expected = FQ(UINT_MAX << n)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    actual = proxy_contract.functions.shl(fp_a_repr, n).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_small(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(3), FQ(3)
    expected = FQ(9)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(3)
    expected = FQ(UINT_MAX * 3)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(0xf12387)
    expected = FQ(UINT_MAX * 0xf12387)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium_3(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(10)
    expected = FQ(UINT_MAX * 10)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium_4(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 10), FQ(1)
    expected = FQ(UINT_MAX*10)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_medium_5(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(UINT_MAX * 10)
    expected = FQ(UINT_MAX*10)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_big_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(0xf12387)
    expected = FQ(UINT_MAX * 0xf12387)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmul_big_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX+10), FQ(0xf12387)
    expected = FQ((UINT_MAX+10) * 0xf12387)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lmul(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)


def test_ladd_fq2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ2([FQ(1), FQ(1)]), FQ2([FQ(2), FQ(2)])
    expected = (FQ(3), FQ(3))
    fp_a_repr = _convert_int_to_fp2_repr(fp_a)
    fp_b_repr = _convert_int_to_fp2_repr(fp_b)
    actual = proxy_contract.functions.ladd(fp_a_repr, fp_b_repr).call()
    actual = tuple(_convert_fp_to_int(fp2_repr) for fp2_repr in actual)
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == actual

def test_lpow_as_mod(fplib_contract):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(field_modulus + 1)
    expected = FQ(1)
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lpow(fp_repr, 1).call()
    actual = _convert_fp_to_int(actual)

    print(f"actual: {type(actual)}")
    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual

def test_lpow_small_exp_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(FQ.field_modulus - 1)
    expected = FQ(fp)
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lpow(fp_repr, 1).call()
    actual = _convert_fp_to_int(actual)

    # print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"actual: {actual}")
    print(f"expected: {expected}")

    assert expected == actual

def test_lsquare_small_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(10)
    expected = FQ(100)
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    # print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"actual: {int.from_bytes(actual, 'big')}")
    print(f"expected: {expected}")

    assert expected == int.from_bytes(actual, 'big')

def test_lsquare_small_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(2)
    expected = FQ(4)
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    # print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"actual: {int.from_bytes(actual, 'big')}")
    print(f"expected: {expected}")

    assert expected == int.from_bytes(actual, 'big')

def test_lsquare_small_3(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(1)
    expected = FQ(1)
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    # print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"actual: {int.from_bytes(actual, 'big')}")
    print(f"expected: {expected}")

    assert expected == int.from_bytes(actual, 'big')

def test_lsquare_medium_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(UINT_32_MAX)
    expected = fp*fp
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    # print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lsquare_medium_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(UINT_64_MAX)
    expected = fp*fp
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lsquare_medium_3(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(UINT_MAX)
    expected = fp*fp
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lsquare_big(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(FQ.field_modulus - 1)
    expected = fp*fp
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"expected: {expected}")
    print(f"expected: {expected}")
    print(f"fq: {FQ.field_modulus}")

    assert expected == _convert_fp_to_int(actual)

def test_lsquare_big_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp = FQ(FQ.field_modulus - 10)
    expected = fp*fp
    fp_repr = _convert_int_to_fp_repr(fp)
    actual = fplib_contract.functions.lsquare(fp_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    # print(f"actual: {actual}")
    print(f"actual: {type(actual)}")
    print(f"expected: {expected}")
    print(f"expected: {expected}")
    print(f"fq: {FQ.field_modulus}")
    print(f"actual - fq: {_convert_fp_to_int(actual) - FQ.field_modulus}")

    assert expected == _convert_fp_to_int(actual)

@pytest.mark.skip(reason="no way of currently testing this")
def test_ladd_G2_1(proxy_contract, signing_root, dst):
    expected1 = proxy_contract.functions.hashToCurve(signing_root).call()
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    expected = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    # spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # expected1 = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    first_g2 = points[0]
    second_g2 = points[1]
    # print(f"expected: {expected}")
    # print(f"actual: {spec_result}")
    actual1 = proxy_contract.functions.addG2NoPrecompile(first_g2, second_g2).call()
    actual = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in actual1)

    # print(f"actual: {actual}")
    # print(f"actual: {actual}")
    for i ,v in enumerate(actual1):
        print(f"actual {i}: {v}")
    # print(f"expected: {expected}")
    for i ,v in enumerate(expected1):
        print(f"expected {i}: {v}")
    assert actual == expected

def test_lmod_small_7(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a = FQ(33)
    fp_b = FQ(10)
    expected = FQ(3)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_small_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(10), FQ(10)
    expected = FQ(0)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_small_2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(100), FQ(10)
    expected = FQ(0)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)


def test_lmod_small_3(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(8), FQ(10)
    expected = FQ(8)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_small_4(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(18), FQ(10)
    expected = FQ(8)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_small_5(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(18), FQ(9)
    expected = FQ(0)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_small_6(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(19), FQ(9)
    expected = FQ(1)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_medium_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX + 10), FQ(UINT_MAX + 10)
    expected = FQ(0)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()
    actual = _convert_fp_to_int(actual)
    # assert actual < _convert_fp_to_int(fp_b), "wtf"
    print(f"actual: {actual}")
    print(f"expected: {expected}")
    print(f"fp_a: {fp_a}")
    print(f"fp_b: {fp_b}")
    print(f"uintmax: {UINT_MAX}")
    assert expected == actual

def test_lmod_medium_2(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 10 + 10), FQ(UINT_MAX)
    expected = FQ(10)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_medium_3(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(115792089237316195423570985008687907853269984665640564039457584007913129639945), FQ(UINT_MAX)
    expected = FQ(10)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_big_1(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(FQ.field_modulus-2), FQ(FQ.field_modulus-1)
    expected = fp_a

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_big_2(proxy_contract):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(field_modulus+2), FQ(field_modulus)
    expected = FQ(2)

    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")

    assert expected == _convert_fp_to_int(actual)

def test_lmod_base_field(proxy_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ((FQ.field_modulus-1)*5 + 100), FQ(FQ.field_modulus-1)
    expected = FQ(95)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lmod_really_big(proxy_contract):
    FQ.field_modulus = 0xffa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    contract_field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ((contract_field_modulus*100+1)), FQ(contract_field_modulus)
    expected = FQ(1)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = proxy_contract.functions.lmod(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_ladd_big_1(fplib_contract):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(field_modulus - 2), FQ(100)
    expected = FQ(98)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"fp_a big1: {_convert_fp_to_int(fp_a_repr)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_ladd_big_2(fplib_contract):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(100), FQ(field_modulus - 2)
    expected = FQ(98)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    print(f"fp_b big2: {_convert_fp_to_int(fp_b_repr)}")
    assert expected == _convert_fp_to_int(actual)

def test_ladd_big_3(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(100+FQ.field_modulus), FQ(FQ.field_modulus-10)
    expected = FQ(90)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_ladd_big_4(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(2), FQ(FQ.field_modulus-1)
    actual = FQ(fp_a + fp_b)
    expected = FQ(1)
    assert actual == expected
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    print(f"expected: {_convert_fp_to_int(fp_b_repr)}")
    # assert _convert_fp_to_int(actual- 1) == FQ.field_modulus - 1
    assert expected == _convert_fp_to_int(actual)

def test_ladd_big_5(fplib_contract):
    FQ.field_modulus = 0xfa0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(field_modulus-1)
    expected = FQ(0)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    print(f"field_modulus: {_convert_fp_to_int(fp_b_repr)}")
    # assert _convert_fp_to_int(actual) == field_modulus
    assert expected == _convert_fp_to_int(actual)

def test_ladd_medium(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(UINT_MAX)
    expected = FQ(UINT_MAX * 2)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_ladd_small(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(2)
    expected = FQ(3)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.ladd(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_small(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(50), FQ(10)
    expected = FQ(40)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_medium_1(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX * 2), FQ(UINT_MAX)
    expected = FQ(UINT_MAX)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)


def test_lsub_medium_2(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX+1), FQ(UINT_MAX)
    expected = FQ(1)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_medium_3(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX*10), FQ(UINT_MAX*10)
    expected = FQ(0)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_medium_4(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX*10 + 10), FQ(UINT_MAX*10)
    expected = FQ(10)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_medium_5(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(UINT_MAX), FQ(45442060874369865957053122457065728162598490762543039060009208264153100167950)
    expected = fp_a-fp_b
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()

    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)

def test_lsub_big(fplib_contract):
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(FQ.field_modulus-1), FQ(UINT_MAX)
    expected = FQ(FQ.field_modulus - UINT_MAX - 1)
    fp_a_repr = _convert_int_to_fp_repr(fp_a)
    fp_b_repr = _convert_int_to_fp_repr(fp_b)
    actual = fplib_contract.functions.lsub(fp_a_repr, fp_b_repr).call()
    print(f"actual: {_convert_fp_to_int(actual)}")
    print(f"expected: {expected}")
    assert expected == _convert_fp_to_int(actual)


def test_add():
    FQ.field_modulus = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    fp_a, fp_b = FQ(1), FQ(2)
    expected = FQ(3)
    actual = fp_a + fp_b
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

@pytest.mark.skip(reason="no way of currently testing this")
def test_hash_to_curve_no_precompile_matches_spec(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurveNoPrecompile(signing_root).call()
    expected1 = proxy_contract.functions.hashToCurve(signing_root).call()
    points = proxy_contract.functions.signature_to_g2_points(signing_root).call()
    converted_expected = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    # expected1 = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in expected1)
    first_g2 = points[0]
    second_g2 = points[1]
    print(f"expected: {converted_expected}")
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
    assert converted_expected == spec_result
    assert converted_result == spec_result

@pytest.mark.skip(reason="no way of currently testing this")
def test_hash_to_curve_no_precompile_matches_spec_2(proxy_contract, signing_root, dst):
    result = proxy_contract.functions.hashToCurveNoPrecompile(signing_root).call()
    expected = proxy_contract.functions.hashToCurve(signing_root).call()
    converted_result = tuple(_convert_fp2_to_int(fp2_repr) for fp2_repr in result)
    # spec_result = normalize(hash_to_G2(signing_root, dst, hashlib.sha256))
    # print(f"expected: {converted_result}")
    # print(f"actual: {spec_result}")
    assert expected == result


# @pytest.mark.skip(reason="function was commented out due to gas issues")
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


@pytest.mark.skip(reason="function was commented out due to gas issues")
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


@pytest.mark.skip(reason="function was commented out due to gas issues")
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
    public_key_witness_repr = _convert_int_to_fp_repr(public_key_witness)

    signature_witness_repr = _convert_int_to_fp2_repr(signature_witness)

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
