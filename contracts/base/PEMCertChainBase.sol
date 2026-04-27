// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BytesUtils} from "../utils/BytesUtils.sol";

import {LibString} from "solady/utils/LibString.sol";
import {PCKHelper, X509CertObj} from "@automata-network/on-chain-pccs/helpers/PCKHelper.sol";
import {X509CRLHelper} from "@automata-network/on-chain-pccs/helpers/X509CRLHelper.sol";
import {PcsDao, CA} from "@automata-network/on-chain-pccs/bases/PcsDao.sol";

struct PCKCertTCB {
    uint16 pcesvn;
    uint8[] cpusvns;
    bytes fmspcBytes;
    bytes pceidBytes;
}

abstract contract PEMCertChainBase {
    using BytesUtils for bytes;

    PCKHelper public pckHelper;
    X509CRLHelper public crlHelper;
    PcsDao public pcsDao;
    address public p256Verifier;

    /// @dev https://github.com/daimo-eth/p256-verifier/blob/master/src/P256.sol
    address internal constant DEFAULT_P256_VERIFIER = 0xc2b78104907F722DABAc4C69f826a522B2754De4;
    address internal constant NATIVE_P256_VERIFIER = 0x0000000000000000000000000000000000000100;

    string constant PLATFORM_ISSUER_NAME = "Intel SGX PCK Platform CA";
    string constant PROCESSOR_ISSUER_NAME = "Intel SGX PCK Processor CA";

    // keccak256(hex"0ba9c4c0c0c86193a3fe23d6b02cda10a8bbd4e88e48b4458561a36e705525f567918e2edc88e40d860bd0cc4ee26aacc988e505a953558c453f6b0904ae7394")
    // the uncompressed (0x04) prefix is not included in the pubkey pre-image
    bytes32 constant ROOTCA_PUBKEY_HASH = 0x89f72d7c488e5b53a77c23ebcb36970ef7eb5bcf6658e9b8292cfbe4703a8473;

    constructor(address _pckHelper, address _crlHelper, address _pcsDao, address _p256Verifier) {
        _setCertBaseConfig(_pckHelper, _crlHelper, _pcsDao, _p256Verifier);
    }

    function _setCertBaseConfig(address _pckHelper, address _crlHelper, address _pcsDao, address _p256Verifier) internal {
        pckHelper = PCKHelper(_pckHelper);
        crlHelper = X509CRLHelper(_crlHelper);
        pcsDao = PcsDao(_pcsDao);
        p256Verifier = _p256Verifier == address(0) ? DEFAULT_P256_VERIFIER : _p256Verifier;
    }

    function _parsePck(bytes memory der, uint256 extensionPtr) internal view returns (PCKCertTCB memory pckTCB) {
        (pckTCB.pcesvn, pckTCB.cpusvns, pckTCB.fmspcBytes, pckTCB.pceidBytes) =
            pckHelper.parsePckExtension(der, extensionPtr);
    }

    function _verifyCertChain(X509CertObj[] memory certs) internal view returns (bool) {
        uint256 n = certs.length;
        bool certRevoked;
        bool certNotExpired;
        bool verified;
        bool certChainCanBeTrusted;
        for (uint256 i = 0; i < n; i++) {
            X509CertObj memory issuer;
            if (i == n - 1) {
                // rootCA
                issuer = certs[i];
            } else {
                issuer = certs[i + 1];
                bytes memory crl;
                if (i == n - 2) {
                    (, crl) = pcsDao.getCertificateById(CA.ROOT);
                } else if (i == 0) {
                    string memory issuerName = certs[i].issuerCommonName;
                    if (LibString.eq(issuerName, PLATFORM_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PLATFORM);
                    } else if (LibString.eq(issuerName, PROCESSOR_ISSUER_NAME)) {
                        (, crl) = pcsDao.getCertificateById(CA.PROCESSOR);
                    } else {
                        return false;
                    }
                }
                if (crl.length > 0) {
                    certRevoked = crlHelper.serialNumberIsRevoked(certs[i].serialNumber, crl);
                }
                if (certRevoked) {
                    break;
                }
            }

            certNotExpired = block.timestamp > certs[i].validityNotBefore && block.timestamp < certs[i].validityNotAfter;
            if (!certNotExpired) {
                break;
            }

            {
                verified = _ecdsaVerify(sha256(certs[i].tbs), certs[i].signature, issuer.subjectPublicKey);
                if (!verified) {
                    break;
                }
            }

            bytes32 issuerPubKeyHash = keccak256(issuer.subjectPublicKey);

            if (issuerPubKeyHash == ROOTCA_PUBKEY_HASH) {
                certChainCanBeTrusted = true;
                break;
            }
        }
        return !certRevoked && certNotExpired && verified && certChainCanBeTrusted;
    }

    function _getCertHash(CA ca) internal view returns (bool success, bytes32 certHash) {
        bytes32 key = pcsDao.PCS_KEY(ca, false);
        try pcsDao.getCollateralHash(key) returns (bytes32 hash) {
            certHash = hash;
            success = true;
        } catch {
            success = false;
        }
    }

    function _getCrlHash(CA ca) internal view returns (bool success, bytes32 crlHash) {
        bytes32 key = pcsDao.PCS_KEY(ca, true);
        try pcsDao.getCollateralHash(key) returns (bytes32 hash) {
            crlHash = hash;
            success = true;
        } catch {
            success = false;
        }
    }

    function _ecdsaVerify(bytes32 messageHash, bytes memory signature, bytes memory key)
        internal
        view
        returns (bool verified)
    {
        bytes memory args = abi.encode(
            messageHash,
            uint256(bytes32(signature.substring(0, 32))),
            uint256(bytes32(signature.substring(32, 32))),
            uint256(bytes32(key.substring(0, 32))),
            uint256(bytes32(key.substring(32, 32)))
        );
        (bool hasResult, bool nativeVerified) = _tryP256Verify(p256Verifier, args);
        if (hasResult) {
            return nativeVerified;
        }

        if (p256Verifier != DEFAULT_P256_VERIFIER) {
            (hasResult, verified) = _tryP256Verify(DEFAULT_P256_VERIFIER, args);
            assert(hasResult); // require either configured verifier or fallback contract
            return verified;
        }

        if (p256Verifier != NATIVE_P256_VERIFIER) {
            (hasResult, verified) = _tryP256Verify(NATIVE_P256_VERIFIER, args);
            if (hasResult) {
                return verified;
            }
        }

        assert(false); // no working P256 verifier available
    }

    function _tryP256Verify(address verifier, bytes memory args) private view returns (bool hasResult, bool verified) {
        (bool success, bytes memory ret) = verifier.staticcall(args);
        if (!success || ret.length != 32) {
            return (false, false);
        }

        hasResult = true;
        verified = abi.decode(ret, (uint256)) == 1;
    }
}
