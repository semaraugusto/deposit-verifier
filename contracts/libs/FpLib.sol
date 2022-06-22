// SPDX-License-Identifier: The Unlicense
pragma solidity 0.8.14;
pragma experimental ABIEncoderV2;

import { Math } from "./math.sol";

library FpLib  {
    /* constructor() {} */
    uint256 constant BLS_BASE_FIELD_B = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint256 constant BLS_BASE_FIELD_A = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint8 constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;
    struct Fp {
        uint a;
        uint b;
    }

    function convertSliceToFpUnchecked(bytes memory data) internal pure returns (Fp memory result) {
        uint a = Math.sliceToUint(data, 0, 16);
        uint b = Math.sliceToUint(data, 16, 48);
        return Fp(a, b);
    }

    function convertSliceToFp(bytes memory data, uint start, uint end) internal view returns (Fp memory result) {
        bytes memory fieldElement = Math.reduceModulo(data, start, end);
        uint a = Math.sliceToUint(fieldElement, 0, 16);
        uint b = Math.sliceToUint(fieldElement, 16, 48);
        return Fp(a, b);
    }

    function lmulUnchecked(Fp memory x, Fp memory y) internal view returns (uint, uint, uint) {
        uint r0;
        uint r1;
        uint r2;
        uint pb;
        uint pa;
        uint carry;
        /* Fp memory p;  */

        (pa, pb) = Math.lmul(x.b, y.b);

        r0 = pb;
        r1 = pa;

        (pa, pb) = Math.lmul(x.a, y.b);
        (r1, carry) = Math.add(r1, pb, carry);
        (r2, carry) = Math.add(0, pa, carry);
        require(carry == 0, "overflow");

        (pa, pb) = Math.lmul(x.b, y.a);
        (r1, carry) = Math.add(r1, pb, carry);
        (r2, carry) = Math.add(r2, pa, carry);
        require(carry == 0, "overflow");

        (pa, pb) = Math.lmul(x.a, y.a);
        (r2, carry) = Math.add(r2, pb, carry);
        require(carry == 0, "overflow");
        require(pa == 0, "overflow");

        return (r2, r1, r0);
    }
    function lmul(Fp memory x, Fp memory y) internal view returns (Fp memory) {
        uint r0;
        uint r1;
        uint r2;
        uint pb;
        uint pa;
        uint carry;
        /* Fp memory p;  */

        (pa, pb) = Math.lmul(x.b, y.b);

        r0 = pb;
        r1 = pa;

        (pa, pb) = Math.lmul(x.a, y.b);
        (r1, carry) = Math.add(r1, pb, carry);
        (r2, carry) = Math.add(0, pa, carry);
        require(carry == 0, "overflow");

        (pa, pb) = Math.lmul(x.b, y.a);
        (r1, carry) = Math.add(r1, pb, carry);
        (r2, carry) = Math.add(r2, pa, carry);
        require(carry == 0, "overflow");

        (pa, pb) = Math.lmul(x.a, y.a);
        (r2, carry) = Math.add(r2, pb, carry);
        require(carry == 0, "overflow");
        require(pa == 0, "overflow");

        Fp memory result = Fp(r1, r0);
        Fp memory base_field = get_base_field();
        if(r2 == 0 && lgte(result, base_field)) {
            return result;
        }
        /* Fp memory partial_res = ldiv(x, p); */
        /* partial_res = lmul(partial_res, p); */
        /* return lsub(x, partial_res); */

        uint length = 32;
        /* bytes memory data = ; */
        bytes memory data = abi.encodePacked([r0]);
        if(r2 > 0) {
            length = 96;
            data = abi.encodePacked([r2, r1, r0]);
            /* return expmod(data, 1, length); */
            /* return res */
        } else {
            length = 64;
            data = abi.encodePacked([r1, r0]);
        }
        result = expmod(data, 1, length);
        return lmod(result, base_field);
    }
    function lgte(Fp memory x, Fp memory y) internal pure returns (bool) {
        uint r0;
        uint r1;
        uint carry = 0;
        (r1, carry) = Math.lsub(x.a, y.a, carry);
        // if overflowed then its lt
        if(carry != 0) {
            return false;
        }
        else if(r1 > 0) {
            return true;
        }
        else if(r1 == 0) {
            carry = 0;
            (r0, carry) = Math.lsub(x.b, y.b, carry);
            if(carry != 0) {
                return false;
            }
        }
        return true;
    }
    function expmod(bytes memory data, uint exponent, uint length) internal view returns (Fp memory) {
        assert (length >= 0);
        assert (length <= data.length);

        bytes memory result = new bytes(48);

        bool success;
        assembly {
            let p := mload(0x40)
            // length of base
            mstore(p, length)
            // length of exponent
            mstore(add(p, 0x20), 0x20)
            // length of modulus
            mstore(add(p, 0x40), 48)
            // base
            // first, copy slice by chunks of EVM words
            let ctr := length
            let src := add(add(data, 0x20), 0)
            let dst := add(p, 0x60)
            for { }
                or(gt(ctr, 0x20), eq(ctr, 0x20))
                { ctr := sub(ctr, 0x20) }
            {
                mstore(dst, mload(src))
                dst := add(dst, 0x20)
                src := add(src, 0x20)
            }
            // next, copy remaining bytes in last partial word
            let mask := sub(exp(256, sub(0x20, ctr)), 1)
            let srcpart := and(mload(src), not(mask))
            let destpart := and(mload(dst), mask)
            mstore(dst, or(destpart, srcpart))
            // exponent
            mstore(add(p, add(0x60, length)), exponent)
            // modulus
            let modulusAddr := add(p, add(0x60, add(0x10, length)))
            mstore(modulusAddr, or(mload(modulusAddr), 0x1a0111ea397fe69a4b1ba7b6434bacd7)) // pt 1
            mstore(add(p, add(0x90, length)), 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab) // pt 2
            success := staticcall(
                sub(gas(), 2000),
                MOD_EXP_PRECOMPILE_ADDRESS,
                p,
                add(0xB0, length),
                add(result, 0x20),
                48)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to modular exponentiation precompile failed");
        return convertSliceToFpUnchecked(result);
    }

    function lmod(Fp memory x, Fp memory p) internal view returns (Fp memory) {
        if (lgte(x, p)) {
            Fp memory partial_res = ldiv(x, p);
            partial_res = lmul(partial_res, p);
            return lsub(x, partial_res);
        } else {
            return x;
        }
    }
    function get_base_field() internal pure returns (Fp memory) {
        return Fp(BLS_BASE_FIELD_A, BLS_BASE_FIELD_B);
    }
    function ldiv(Fp memory x, Fp memory y) internal view returns (Fp memory) { unchecked {
        require((y.a != 0 || y.b != 0), "division by zero");
        if((x.a == y.a) && (x.b == y.b)) {
            return Fp(0, 1);
        }
        uint x_bit_length = bitLength(x);
        uint y_bit_length = bitLength(y);
        Fp memory one = Fp(0, 1);
        Fp memory p;
        while(x_bit_length > y_bit_length) {
            uint shift = x_bit_length - y_bit_length - 1;
            p = ladd(p, shl(one, shift));
            x = lsub(x, shl(y, shift));
            x_bit_length = bitLength(x);
        }
        if (lgte(x, y)) {
            return ladd(p, one);
        }

        return p;
    }}
    function ladd(Fp memory x, Fp memory y) internal view returns (Fp memory) { unchecked {
        uint r0;
        uint r1;
        uint carry;
        (r0, carry) = Math.add(x.b, y.b, carry);
        (r1, carry) = Math.add(x.a, y.a, carry);
        require(carry == 0, "overflow");

        Fp memory result = Fp(r1, r0);
        Fp memory base_field = get_base_field();
        return lmod(result, base_field);
        /* return result; */
    }}
    function shl(Fp memory x, uint256 n) internal pure returns (Fp memory) { unchecked {
        if (x.a == 0 && x.b == 0)
            return x;
        
        uint256 bits_shift = n % 256;
        uint256 comp_shift = 256 - bits_shift;

        /* uint256 remainder = 0; */

        uint256 u = x.b;
        uint r0 = u << n;
        uint remainder = u >> comp_shift;
        u = x.a;
        uint r1 = u << n | remainder;
        remainder = u >> comp_shift;
        require(remainder == 0, "overflow");

        return Fp(r1, r0);
    }}
    function bitLength(Fp memory p) internal pure returns (uint256) { unchecked {
        if (p.a > 0) {
            uint a_length = Math.bitLength(p.a);
            return a_length + 256;
        }
        return Math.bitLength(p.b);
        /* bitLength(p.b); */
    }}
    /* function fp_mul(Fp memory x, Fp memory y) internal view returns (Fp memory) { */
    /*     uint r0; */
    /*     uint r1; */
    /*     uint r2; */
    /*     uint pb; */
    /*     uint pa; */
    /*     uint carry; */
    /**/
    /*     (pa, pb) = Math.lmul(x.b, y.b); */
    /**/
    /*     r0 = pb; */
    /*     r1 = pa; */
    /**/
    /*     (pa, pb) = Math.lmul(x.a, y.b); */
    /*     (r1, carry) = Math.add(r1, pb, carry); */
    /*     (r2, carry) = Math.add(0, pa, carry); */
    /*     require(carry == 0, "overflow"); */
    /**/
    /*     (pa, pb) = Math.lmul(x.b, y.a); */
    /*     (r1, carry) = Math.add(r1, pb, carry); */
    /*     (r2, carry) = Math.add(r2, pa, carry); */
    /*     require(carry == 0, "overflow"); */
    /**/
    /*     (pa, pb) = Math.lmul(x.a, y.a); */
    /*     (r2, carry) = Math.add(r2, pb, carry); */
    /*     require(carry == 0, "overflow"); */
    /*     require(pa == 0, "overflow"); */
    /**/
    /*     Fp memory result = Fp(r1, r0); */
    /*     Fp memory base_field = get_base_field(); */
    /*     if(r2 == 0 && lgte(result, base_field)) { */
    /*         return result; */
    /*     } */
    /**/
    /*     uint length = 32; */
    /*     bytes memory data = abi.encodePacked([r0]); */
    /*     if(r2 > 0) { */
    /*         length = 96; */
    /*         data = abi.encodePacked([r2, r1, r0]); */
    /*     } else { */
    /*         length = 64; */
    /*         data = abi.encodePacked([r1, r0]); */
    /*     } */
    /*     result = expmod(data, 1, length); */
    /*     return lmod(result, base_field); */
    /* } */
    function lsubUnchecked(FpLib.Fp memory x, FpLib.Fp memory y) internal pure returns (FpLib.Fp memory) { unchecked {
        uint r0;
        uint r1;
        uint carry = 0;
        (r0, carry) = Math.lsub(x.b, y.b, carry);
        (r1, carry) = Math.lsub(x.a, y.a, carry);
        if(carry > 0) {
            FpLib.Fp memory base_field = get_base_field();
            return lsub(base_field, FpLib.Fp(0, carry));
        }
        return FpLib.Fp(r1, r0);
    }}
    function lsub(Fp memory x, Fp memory y) internal pure returns (Fp memory) { unchecked {
        uint r0;
        uint r1;
        uint carry = 0;
        (r0, carry) = Math.lsub(x.b, y.b, carry);
        (r1, carry) = Math.lsub(x.a, y.a, carry);
        require(carry == 0, "underflow");
        return Fp(r1, r0);
    }}
    function lsquare(Fp memory x) internal view returns (Fp memory) {
        return lpow(x, 2);
    }
    function lpow(Fp memory x, uint exp) internal view returns (Fp memory) {
        uint r1 = x.a;
        uint length = 32;
        uint r0 = x.b;
        FpLib.Fp memory result;
        bytes memory data;
        if (r1 > 0) {
            length = 64;
            data = abi.encodePacked([r1, r0]);
            result = expmod(data, exp, length);
            return result;
        }
        data = abi.encodePacked([r0]);
        result = expmod(data, exp, length);
        return result;
    }
    function leq(FpLib.Fp memory x, FpLib.Fp memory y) internal pure returns (bool) {
        return(x.a == y.a && x.b == y.b);
    }
}
