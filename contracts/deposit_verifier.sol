// SPDX-License-Identifier: The Unlicense
pragma solidity 0.8.14;
pragma experimental ABIEncoderV2;

contract DepositVerifier  {
    uint constant PUBLIC_KEY_LENGTH = 48;
    uint constant SIGNATURE_LENGTH = 96;
    uint constant WITHDRAWAL_CREDENTIALS_LENGTH = 32;
    uint constant WEI_PER_GWEI = 1e9;
    uint constant UINT_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    uint8 constant BLS12_381_PAIRING_PRECOMPILE_ADDRESS = 0x10;
    uint8 constant BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS = 0x12;
    uint8 constant BLS12_381_G2_ADD_ADDRESS = 0xD;
    string constant BLS_SIG_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_+";
    bytes1 constant BLS_BYTE_WITHOUT_FLAGS_MASK = bytes1(0x1f);
    uint8 constant MOD_EXP_PRECOMPILE_ADDRESS = 0x5;

    event Add(uint r0, uint r1);
    // Fp is a field element with the high-order part stored in `a`.
    struct Fp {
        uint a;
        uint b;
    }

    // Fp2 is an extension field element with the coefficient of the
    // quadratic non-residue stored in `b`, i.e. p = a + i * b
    struct Fp2 {
        Fp a;
        Fp b;
    }

    // G1Point represents a point on BLS12-381 over Fp with coordinates (X,Y);
    struct G1Point {
        Fp X;
        Fp Y;
    }

    // G2Point represents a point on BLS12-381 over Fp2 with coordinates (X,Y);
    struct G2Point {
        Fp2 X;
        Fp2 Y;
    }
    uint256 constant BLS_BASE_FIELD_B = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;
    uint256 constant BLS_BASE_FIELD_A = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    /* Fp constant BASE_FIELD = Fp(BLS_BASE_FIELD_A, BLS_BASE_FIELD_B); */
    // uint constant BLS12_381_BASE_FIELD_MODULUS = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    // uint constant BLS12_381_FP_QR_RES = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa;
    //
    // uint constant BLS12_381_G1_X = 0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb;
    // uint constant BLS12_381_G1_Y = 0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1;
    //
    // uint constant BLS12_381_G2_P1_X = 0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8;
    // uint constant BLS12_381_G2_P1_Y = 0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801;
    // uint constant BLS12_381_G2_P2_X = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e;
    // uint constant BLS12_381_G2_P2_Y = 0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be;
    //
    // Constant related to versioning serializations of deposits on eth2
    bytes32 immutable DEPOSIT_DOMAIN;

    uint256 MAX_U256 = 2**256-1;

    constructor(bytes32 deposit_domain) {
        DEPOSIT_DOMAIN = deposit_domain;
    }

    // Return a `wei` value in units of Gwei and serialize as a (LE) `bytes8`.
    function serializeAmount(uint amount) private pure returns (bytes memory) {
        uint depositAmount = amount / WEI_PER_GWEI;

        bytes memory encodedAmount = new bytes(8);

        for (uint i = 0; i < 8; i++) {
            encodedAmount[i] = bytes1(uint8(depositAmount / (2**(8*i))));
        }

        return encodedAmount;
    }

    // Compute the "signing root" from the deposit message. This root is the Merkle root
    // of a specific tree specified by SSZ serialization that takes as leaves chunks of 32 bytes.
    // NOTE: This computation is done manually in ``computeSigningRoot``.
    // NOTE: function is exposed for testing...
    function computeSigningRoot(
        bytes memory publicKey,
        bytes memory withdrawalCredentials,
        uint amount
    ) public view returns (bytes32) {
        bytes memory serializedPublicKey = new bytes(64);
        for (uint i = 0; i < PUBLIC_KEY_LENGTH; i++) {
            serializedPublicKey[i] = publicKey[i];
        }

        bytes32 publicKeyRoot = sha256(serializedPublicKey);
        bytes32 firstNode = sha256(abi.encodePacked(publicKeyRoot, withdrawalCredentials));

        bytes memory amountRoot = new bytes(64);
        bytes memory serializedAmount = serializeAmount(amount);
        for (uint i = 0; i < 8; i++) {
            amountRoot[i] = serializedAmount[i];
        }
        bytes32 secondNode = sha256(amountRoot);

        bytes32 depositMessageRoot = sha256(abi.encodePacked(firstNode, secondNode));
        return sha256(abi.encodePacked(depositMessageRoot, DEPOSIT_DOMAIN));
    }


    // NOTE: function exposed for testing...
    function expandMessage(bytes32 message) public pure returns (bytes memory) {
        bytes memory b0Input = new bytes(143);
        for (uint i = 0; i < 32; i++) {
            b0Input[i+64] = message[i];
        }
        b0Input[96] = 0x01;
        for (uint i = 0; i < 44; i++) {
            b0Input[i+99] = bytes(BLS_SIG_DST)[i];
        }

        bytes32 b0 = sha256(abi.encodePacked(b0Input));

        bytes memory output = new bytes(256);
        bytes32 chunk = sha256(abi.encodePacked(b0, bytes1(0x01), bytes(BLS_SIG_DST)));
        assembly {
            mstore(add(output, 0x20), chunk)
        }
        for (uint i = 2; i < 9; i++) {
            bytes32 input;
            assembly {
                input := xor(b0, mload(add(output, add(0x20, mul(0x20, sub(i, 2))))))
            }
            chunk = sha256(abi.encodePacked(input, bytes1(uint8(i)), bytes(BLS_SIG_DST)));
            assembly {
                mstore(add(output, add(0x20, mul(0x20, sub(i, 1)))), chunk)
            }
        }

        return output;
    }

    function sliceToUint(bytes memory data, uint start, uint end) private pure returns (uint) {
        uint length = end - start;
        assert(length >= 0);
        assert(length <= 32);

        uint result;
        for (uint i = 0; i < length; i++) {
            bytes1 b = data[start+i];
            result = result + (uint8(b) * 2**(8*(length-i-1)));
        }
        return result;
    }

    // Reduce the number encoded as the big-endian slice of data[start:end] modulo the BLS12-381 field modulus.
    // Copying of the base is cribbed from the following:
    // https://github.com/ethereum/solidity-examples/blob/f44fe3b3b4cca94afe9c2a2d5b7840ff0fafb72e/src/unsafe/Memory.sol#L57-L74
    function reduceModulo(bytes memory data, uint start, uint end) private view returns (bytes memory) {
        uint length = end - start;
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
            let src := add(add(data, 0x20), start)
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
            mstore(add(p, add(0x60, length)), 1)
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
        return result;
    }

    function convertSliceToFp(bytes memory data, uint start, uint end) private view returns (Fp memory result) {
        bytes memory fieldElement = reduceModulo(data, start, end);
        uint a = sliceToUint(fieldElement, 0, 16);
        uint b = sliceToUint(fieldElement, 16, 48);
        return Fp(a, b);
    }

    // NOTE: function is exposed for testing...
    function hashToField(bytes32 message) public view returns (Fp2[2] memory result) {
        bytes memory some_bytes = expandMessage(message);
        result[0] = Fp2(
            convertSliceToFp(some_bytes, 0, 64),
            convertSliceToFp(some_bytes, 64, 128)
        );
        result[1] = Fp2(
            convertSliceToFp(some_bytes, 128, 192),
            convertSliceToFp(some_bytes, 192, 256)
        );
    }

    function mapToCurveNoPrecompile(Fp2 memory fieldElement) public view returns (G2Point memory result) {
        uint[4] memory input;
        input[0] = fieldElement.a.a;
        input[1] = fieldElement.a.b;
        input[2] = fieldElement.b.a;
        input[3] = fieldElement.b.b;

        uint[8] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS,
                input,
                128,
                output,
                256
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to map to curve precompile failed");

        return G2Point(
            Fp2(
                Fp(output[0], output[1]),
                Fp(output[2], output[3])
            ),
            Fp2(
                Fp(output[4], output[5]),
                Fp(output[6], output[7])
            )
        );
    }


    function mapToCurve(Fp2 memory fieldElement) public view returns (G2Point memory result) {
        uint[4] memory input;
        input[0] = fieldElement.a.a;
        input[1] = fieldElement.a.b;
        input[2] = fieldElement.b.a;
        input[3] = fieldElement.b.b;

        uint[8] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_MAP_FIELD_TO_CURVE_PRECOMPILE_ADDRESS,
                input,
                128,
                output,
                256
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to map to curve precompile failed");

        return G2Point(
            Fp2(
                Fp(output[0], output[1]),
                Fp(output[2], output[3])), Fp2( Fp(output[4], output[5]), Fp(output[6], output[7]))
        );
    }

    function G2_isZeroNoPrecompile(Fp2 memory x, Fp2 memory y) public pure returns (bool) {
        return((x.a.a | x.a.b | x.b.a | x.b.b | y.a.a | y.a.b | y.b.a | y.b.b) == 0);
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

    function get_base_field() public pure returns (Fp memory) {
        return Fp(BLS_BASE_FIELD_A, BLS_BASE_FIELD_B);
    }

    function lmod(Fp memory x, Fp memory p) public pure returns (Fp memory) {
        return lsub(x, lmul(ldiv(x, p), p));
    }

    function lgte(Fp memory x, Fp memory y) public pure returns (bool) {
        if(x.a > y.a) {
            return true;
        }
        if(x.a >= y.a) {
            if(x.a == y.a && x.b >= y.b){
                return true;
            }
        }
        return false;
    }
    function bitLength(uint256 n) private pure returns (uint256) { unchecked {
        uint256 m;

        for (uint256 s = 128; s > 0; s >>= 1) {
            if (n >= 1 << s) {
                n >>= s;
                m |= s;
            }
        }

        return m + 1;
    }}

    function bitLength(Fp memory p) private pure returns (uint256) { unchecked {
        return bitLength(p.a) + bitLength(p.b);
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

    function ldiv(Fp memory x, Fp memory y) public pure returns (Fp memory) { unchecked {
        require((y.a != 0 || y.b != 0), "division by zero");
        uint x_bit_length = bitLength(x.a) + bitLength(x.b);
        uint y_bit_length = bitLength(y.a) + bitLength(y.b);
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

    function lsub(Fp2 memory x, Fp2 memory y) public pure returns (Fp2 memory) { unchecked {

        Fp memory a = lsub(x.a, y.a);
        Fp memory b = lsub(x.b, y.b);
        return Fp2(a, b);
    }}

    function lsub(Fp memory x, Fp memory y) public pure returns (Fp memory) { unchecked {
        uint r0;
        uint r1;
        uint carry = 0;
        uint xb = x.b;
        uint xa = x.a;
        uint yb = y.b;
        uint ya = y.a;
        require(xa >= ya, "underflow");
        if (xa == ya) {
            require(xb >= yb, "underflow");
        }

        (r0, carry) = lsub(xb, yb, carry);
        (r1, carry) = lsub(xa, ya, carry);
        require(carry == 0, "underflow");
        /* return compress(result); */
        return Fp(r1, r0);
    }}

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

    function ladd(Fp memory x, Fp memory y) public pure returns (Fp memory) { unchecked {

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
            require(false, "failed");
        }
        /* return lmod(result, base_field); */
        return result;
        /* return lmod(result, get_base_field()); */
    }}

    function ladd(Fp2 memory x, Fp2 memory y) public pure returns (Fp2 memory) { unchecked {
        Fp memory a = ladd(x.a, y.a);
        Fp memory b = ladd(x.b, y.b);
        return Fp2(a, b);
    }}

    function ldouble(Fp memory x) public pure returns (Fp memory) {unchecked {
        return ladd(x, x);
    }}

    function ldouble(Fp2 memory x) public pure returns (Fp2 memory) {unchecked {

         Fp memory a = ldouble(x.a);
         Fp memory b = ldouble(x.b);
         return Fp2(a, b);
    }}

    // This function is being used for testing purposes. 
    function addG2NoPrecompile(G2Point memory a, G2Point memory b) public pure returns (G2Point memory) {
        if(G2_isZeroNoPrecompile(a.X, a.Y)) { return b; }
        if (G2_isZeroNoPrecompile(b.X, b.Y)) { return a; }
        Fp2 memory X = ladd(a.X, b.X);
        Fp2 memory Y = ladd(a.Y, b.Y);

        return G2Point(X, Y);
    }

    function addG2(G2Point memory a, G2Point memory b) private view returns (G2Point memory) {
        uint[16] memory input;
        input[0]  = a.X.a.a;
        input[1]  = a.X.a.b;
        input[2]  = a.X.b.a;
        input[3]  = a.X.b.b;
        input[4]  = a.Y.a.a;
        input[5]  = a.Y.a.b;
        input[6]  = a.Y.b.a;
        input[7]  = a.Y.b.b;

        input[8]  = b.X.a.a;
        input[9]  = b.X.a.b;
        input[10] = b.X.b.a;
        input[11] = b.X.b.b;
        input[12] = b.Y.a.a;
        input[13] = b.Y.a.b;
        input[14] = b.Y.b.a;
        input[15] = b.Y.b.b;

        uint[8] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_G2_ADD_ADDRESS,
                input,
                512,
                output,
                256
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to addition in G2 precompile failed");

        return G2Point(
            Fp2(
                Fp(output[0], output[1]),
                Fp(output[2], output[3])
            ),
            Fp2(
                Fp(output[4], output[5]),
                Fp(output[6], output[7])
            )
        );
    }

    // Implements "hash to the curve" from the IETF BLS draft.
    // NOTE: function is exposed for testing...
    function hashToCurveNoPrecompile(bytes32 message) public view returns (G2Point memory) {
        Fp2[2] memory messageElementsInField = hashToField(message);
        G2Point memory firstPoint = mapToCurve(messageElementsInField[0]);
        G2Point memory secondPoint = mapToCurve(messageElementsInField[1]);
        return addG2NoPrecompile(firstPoint, secondPoint);
    }
    // Implements "hash to the curve" from the IETF BLS draft.
    // NOTE: function is exposed for testing...
    function hashToCurve(bytes32 message) public view returns (G2Point memory) {
        Fp2[2] memory messageElementsInField = hashToField(message);
        G2Point memory firstPoint = mapToCurve(messageElementsInField[0]);
        G2Point memory secondPoint = mapToCurve(messageElementsInField[1]);
        return addG2(firstPoint, secondPoint);
    }

    // NOTE: function is exposed for testing...
    function blsPairingCheck(G1Point memory publicKey, G2Point memory messageOnCurve, G2Point memory signature) public view returns (bool) {
        uint[24] memory input;

        input[0] =  publicKey.X.a;
        input[1] =  publicKey.X.b;
        input[2] =  publicKey.Y.a;
        input[3] =  publicKey.Y.b;

        input[4] =  messageOnCurve.X.a.a;
        input[5] =  messageOnCurve.X.a.b;
        input[6] =  messageOnCurve.X.b.a;
        input[7] =  messageOnCurve.X.b.b;
        input[8] =  messageOnCurve.Y.a.a;
        input[9] =  messageOnCurve.Y.a.b;
        input[10] = messageOnCurve.Y.b.a;
        input[11] = messageOnCurve.Y.b.b;

        // NOTE: this constant is -P1, where P1 is the generator of the group G1.
        input[12] = 31827880280837800241567138048534752271;
        input[13] = 88385725958748408079899006800036250932223001591707578097800747617502997169851;
        input[14] = 22997279242622214937712647648895181298;
        input[15] = 46816884707101390882112958134453447585552332943769894357249934112654335001290;

        input[16] =  signature.X.a.a;
        input[17] =  signature.X.a.b;
        input[18] =  signature.X.b.a;
        input[19] =  signature.X.b.b;
        input[20] =  signature.Y.a.a;
        input[21] =  signature.Y.a.b;
        input[22] =  signature.Y.b.a;
        input[23] =  signature.Y.b.b;

        uint[1] memory output;

        bool success;
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                BLS12_381_PAIRING_PRECOMPILE_ADDRESS,
                input,
                768,
                output,
                32
            )
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success, "call to pairing precompile failed");

        return output[0] == 1;
    }

    function decodeG1Point(bytes memory encodedX, Fp memory Y) private pure returns (G1Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        uint a = sliceToUint(encodedX, 0, 16);
        uint b = sliceToUint(encodedX, 16, 48);
        Fp memory X = Fp(a, b);
        return G1Point(X,Y);
    }

    function decodeG2Point(bytes memory encodedX, Fp2 memory Y) private pure returns (G2Point memory) {
        encodedX[0] = encodedX[0] & BLS_BYTE_WITHOUT_FLAGS_MASK;
        // NOTE: the "flag bits" of the second half of `encodedX` are always == 0x0

        // NOTE: order is important here for decoding point...
        uint aa = sliceToUint(encodedX, 48, 64);
        uint ab = sliceToUint(encodedX, 64, 96);
        uint ba = sliceToUint(encodedX, 0, 16);
        uint bb = sliceToUint(encodedX, 16, 48);
        Fp2 memory X = Fp2(
            Fp(aa, ab),
            Fp(ba, bb)
        );
        return G2Point(X, Y);
    }

    // NOTE: function is exposed for testing...
    function blsSignatureIsValid(
        bytes32 message,
        bytes memory encodedPublicKey,
        bytes memory encodedSignature,
        Fp memory publicKeyYCoordinate,
        Fp2 memory signatureYCoordinate
    ) public view returns (bool) {
        G1Point memory publicKey = decodeG1Point(encodedPublicKey, publicKeyYCoordinate);
        G2Point memory signature = decodeG2Point(encodedSignature, signatureYCoordinate);
        G2Point memory messageOnCurve = hashToCurve(message);

        return blsPairingCheck(publicKey, messageOnCurve, signature);
    }
}
