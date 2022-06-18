// SPDX-License-Identifier: The Unlicense
pragma solidity 0.8.14;

import "./Math.sol";

library FpLib  {
    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint a;
        uint b;
    }
    uint constant UINT_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    uint256 constant BLS_BASE_FIELD_B = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint256 constant BLS_BASE_FIELD_A = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    function get_base_field() public pure returns (Fp memory) {
        return Fp(BLS_BASE_FIELD_A, BLS_BASE_FIELD_B);
    }
    function lmul(Fp memory x, Fp memory y) public pure returns (Fp memory result) {
        uint r0;
        uint r1;
        uint r1_carry;
        uint r2_carry;
        uint xb = x.b;
        uint xa = x.a;
        uint yb = y.b;
        uint ya = y.a;
        assembly {
            // multiply least significant bits
            let rem_b := mulmod(xb, yb, not(0))
            r0 := mul(xb, yb)
            r1_carry := sub(sub(rem_b, r0), lt(rem_b, r0))

            // multiply more significant bits
            let rem := mulmod(xa, ya, not(0))
            r1 := mul(xa, ya)
            r2_carry := sub(sub(rem, r1), lt(rem, r1))
            // what to do with this r2_carry? Need to mod with prime base field?
            r1 := add(r1, r1_carry)
        }
        result = Fp(r1, r0);
        Fp memory base_field = get_base_field();
        if (lgte(result, base_field)) {
            return lmod(result, base_field);
        }
        return result;
        /* return Fp(r1, r0); */
    }
    function lgte(Fp memory x, Fp memory y) public pure returns (bool) {
        if(x.a >= y.a) {
            if(x.a == y.a && x.b >= y.b){
                return true;
            }
        }
        return false;
    }
    function lmod(Fp memory x, Fp memory p) public pure returns (Fp memory) {
        return lsub(x, lmul(ldiv(x, p), p));
    }
    function bitLength(Fp memory p) private pure returns (uint256) { unchecked {
        return Math.bitLength(p.a) + Math.bitLength(p.b);
    }}

    function shl(Fp memory x, uint256 n) public pure returns (Fp memory) { unchecked {
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

    function ldiv(Fp memory x, Fp memory y) public pure returns (Fp memory) {
        require((y.a != 0 || y.b != 0), "division by zero");
        uint x_bit_length = Math.bitLength(x.a) + Math.bitLength(x.b);
        uint y_bit_length = Math.bitLength(y.a) + Math.bitLength(y.b);
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
    }

    function lsub(Fp memory x, Fp memory y) public pure returns (Fp memory) {
        uint r0;
        uint r1;
        uint xb = x.b;
        uint xa = x.a;
        uint yb = y.b;
        uint ya = y.a;
        require(xa >= ya, "underflow");
        if (xa == ya) {
            require(xb >= yb, "underflow");
        }

        r1 = xa - ya;
        r1 = 0;
        assembly {
            r0 := sub(xb, yb)
        }
        if(r0 > xb && r1 > 0) {
            assembly {
                r0 := add(r0, UINT_MAX)
                r1 := add(r1, 1)
            }
        }
        return Fp(r1, r0);
    }
    function lsub(uint256 x, uint256 y, uint256 carry) private pure returns (uint256, uint256) { unchecked {
        if (x > 0)
            return lsub(x - carry, y);
        if (y < type(uint256).max)
            return lsub(x, y + carry);
        return (1 - carry, 1);
    }}

    function lsub(uint256 x, uint256 y) private pure returns (uint256, uint256) { unchecked {
        uint256 z = x - y;
        return (z, z > x ? 1 : 0);
    }}

    function ladd(Fp memory x, Fp memory y) public pure returns (Fp memory) {
        uint r0;
        uint r1;
        uint r0_a;
        uint carry_b;
        uint xb = x.b;
        uint xa = x.a;
        uint yb = y.b;
        uint ya = y.a;
        assembly {
            // add least significant bits
            let rem_b := addmod(xb, yb, not(0))
            r0 := add(xb, yb)
            carry_b := sub(sub(rem_b, r0), lt(rem_b, r0))

            // add more significant bits
            let rem := addmod(xa, ya, not(0))
            r0_a := add(xa, ya)
            r1 := sub(sub(rem, r0_a), lt(rem, r0_a))

            // add carry
            r1 := add(r1, carry_b)
            /* r1 := sub(r1, mul(div(r1, BLS_BASE_FIELD_A), BLS_BASE_FIELD_A)) */
            /* r0 := sub(r0, mul(div(r0, BLS_BASE_FIELD_B), BLS_BASE_FIELD_B)) */
        }
        Fp memory result = Fp(r1, r0);
        Fp memory base_field = get_base_field();
        if (lgte(result, base_field)) {
            return lmod(result, base_field);
        }
        return result;
        /* return lmod(result, get_base_field()); */
    }
    function ldouble(Fp memory x) public pure returns (Fp memory) {
        return ladd(x, x);
    }

}
