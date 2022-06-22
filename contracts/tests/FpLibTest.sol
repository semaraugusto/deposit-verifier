// SPDX-License-Identifier: The Unlicense
pragma solidity 0.8.14;
pragma experimental ABIEncoderV2;

import { FpLib } from "../libs/FpLib.sol";

contract FpLibTest  {

    constructor() {}

    function lmul(FpLib.Fp memory x, FpLib.Fp memory y) public view returns (FpLib.Fp memory) {
        return FpLib.lmul(x, y);
    }
    function lgte(FpLib.Fp memory x, FpLib.Fp memory y) public pure returns (bool) {
        return FpLib.lgte(x, y);
    }
    function expmod(bytes memory data, uint exponent, uint length) public view returns (FpLib.Fp memory) {
        return FpLib.expmod(data, exponent, length);
    }

    function lmod(FpLib.Fp memory x, FpLib.Fp memory p) public view returns (FpLib.Fp memory) {
        return FpLib.lmod(x, p);
    }
    function get_base_field() public pure returns (FpLib.Fp memory) {
        return FpLib.get_base_field();
    }
    function ldiv(FpLib.Fp memory x, FpLib.Fp memory y) public view returns (FpLib.Fp memory) { unchecked {
        return FpLib.ldiv(x, y);
    }}
    function ladd(FpLib.Fp memory x, FpLib.Fp memory y) public view returns (FpLib.Fp memory) { unchecked {
        return FpLib.ladd(x, y);
    }}
    function shl(FpLib.Fp memory x, uint256 n) public pure returns (FpLib.Fp memory) { unchecked {
        return FpLib.shl(x, n);
    }}
    function bitLength(FpLib.Fp memory p) public pure returns (uint256) { unchecked {
        return FpLib.bitLength(p);
    }}
    function lsubUnchecked(FpLib.Fp memory x, FpLib.Fp memory y) public pure returns (FpLib.Fp memory) { unchecked {
        return FpLib.lsubUnchecked(x, y);
    }}
    function lsub(FpLib.Fp memory x, FpLib.Fp memory y) public pure returns (FpLib.Fp memory) { unchecked {
        return FpLib.lsub(x, y);
    }}
    function lsquare(FpLib.Fp memory x) public view returns (FpLib.Fp memory) {
        return FpLib.lsquare(x);
    }
    function lpow(FpLib.Fp memory x, uint exp) public view returns (FpLib.Fp memory) {
        return FpLib.lpow(x, exp);
    }
    function leq(FpLib.Fp memory x, FpLib.Fp memory y) public pure returns (bool) {
        return FpLib.leq(x, y);
    }
}
