// SPDX-License-Identifier: The Unlicense
pragma solidity 0.8.14;

library Math  {
    function bitLength(uint256 n) internal pure returns (uint256) { unchecked {
        uint256 m;

        for (uint256 s = 128; s > 0; s >>= 1) {
            if (n >= 1 << s) {
                n >>= s;
                m |= s;
            }
        }

        return m + 1;
    }}
}
