// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

interface IPIEForVerifiedXP {
    struct Identity { bool exists; uint64 xp; uint8 selectedPath; uint8 tier; }
    function getIdentity(address account) external view returns (Identity memory);
}

/// @notice GFLO AR01 V04 CANDIDATE — source-bound signed XP; NOT audited or deployed.
/// @dev Local prototype only. A signature proves WHO attested, not real-world truth.
contract XPPolicyV04SourceBound is EIP712 {
    uint16 public constant MIN_REWARD = 25;
    uint16 public constant MAX_REWARD = 1000;
    uint32 public constant DAILY_CAP = 1500;
    uint32 public constant WEEKLY_CAP = 3000;
    uint16 public constant HIGH_TRUST_FROM = 500;
    uint64 public constant CHALLENGE_PERIOD = 3 days; // PILOT parameter

    bytes32 public constant PROOF_TYPEHASH = keccak256(
        "GFLOEvidence(address recipient,bytes32 ruleId,bytes32 eventId,bytes32 evidenceDigest,uint256 nonce,uint64 issuedAt,uint64 validUntil)"
    );

    bytes32 public constant SOURCE_TYPEHASH = keccak256(
        "GFLOSourceApproval(bytes32 sourceId,address recipient,bytes32 ruleId,bytes32 eventId,bytes32 evidenceDigest,uint256 nonce,uint64 issuedAt,uint64 validUntil,uint64 epoch)"
    );
    struct SourceConfig { bytes32 sourceId; address issuer; uint64 epoch; bool active; }
    mapping(bytes32 => SourceConfig) public ruleSources;
    mapping(bytes32 => bool) public sourceApprovalsUsed;
    error InvalidSource();
    event SourceConfigured(bytes32 indexed ruleId,bytes32 indexed sourceId,address indexed issuer,uint64 epoch,bool active);

    enum Status { NONE, PENDING, VALID, REVOKED }
    struct Rule { uint16 amount; uint32 maxClaims; bool active; }
    struct Proof {
        address recipient;
        bytes32 ruleId;
        bytes32 eventId;
        bytes32 evidenceDigest;
        uint256 nonce;
        uint64 issuedAt;
        uint64 validUntil;
    }
    struct Grant {
        address recipient;
        bytes32 ruleId;
        uint16 amount;
        uint64 finalizesAt;
        address verifier;
        address attestor;
        Status status;
    }

    IPIEForVerifiedXP public immutable pie;
    address public owner;
    bool public paused;
    mapping(address => uint8) public verifierRoles;
    mapping(bytes32 => Rule) public rules;
    mapping(bytes32 => mapping(address => bool)) public ruleAttestors;
    mapping(bytes32 => Grant) public grants;
    // Bind pending grants to the source authorization epoch at submission.
    mapping(bytes32 => uint64) public grantSourceEpoch;
    mapping(bytes32 => bool) public usedEvents;
    mapping(bytes32 => bool) public usedEvidence;
    mapping(bytes32 => bool) public usedProofNonces;
    mapping(address => uint64) public validEarnedXP;
    mapping(address => mapping(bytes32 => uint32)) public claimsPerRule;
    mapping(address => mapping(uint256 => uint32)) public dailyXP;
    mapping(address => mapping(uint256 => uint32)) public weeklyXP;

    error NotOwner();
    error BadSetup();
    error Paused();
    error InvalidRule();
    error InvalidRole();
    error NotVerifier();
    error InvalidProof();
    error InvalidAttestor();
    error ProofExpired();
    error Replay();
    error LimitReached();
    error BadGrantStatus();
    error TooEarly();
    error InvalidIdentity();

    event GrantPending(bytes32 indexed claimId,address indexed recipient,address indexed attestor,uint16 amount,uint64 finalizesAt);
    event GrantFinalized(bytes32 indexed claimId,address indexed recipient,uint16 amount);
    event GrantRevoked(bytes32 indexed claimId,address indexed recipient,uint16 amount,bytes32 reason);
    event PausedChanged(bool state);
    event VerifierChanged(address indexed verifier,uint8 role);
    event AttestorChanged(bytes32 indexed ruleId,address indexed attestor,bool allowed);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    constructor(address core,address safeOwner) EIP712("GFLO XP Evidence","4") {
        if (core.code.length == 0 || safeOwner == address(0)) revert BadSetup();
        pie = IPIEForVerifiedXP(core);
        owner = safeOwner;
    }

    function setPaused(bool state) external onlyOwner {
        paused=state; emit PausedChanged(state);
    }
    function setVerifierRole(address verifier,uint8 role) external onlyOwner {
        if(verifier==address(0) || role>2) revert InvalidRole();
        verifierRoles[verifier]=role; emit VerifierChanged(verifier,role);
    }
    function registerRule(bytes32 ruleId,uint16 amount,uint32 maxClaims) external onlyOwner {
        if(ruleId==bytes32(0)||amount<MIN_REWARD||amount>MAX_REWARD||maxClaims==0||rules[ruleId].maxClaims!=0) revert InvalidRule();
        rules[ruleId]=Rule(amount,maxClaims,true);
    }
    function setAttestor(bytes32 ruleId,address attestor,bool allowed) external onlyOwner {
        if(rules[ruleId].maxClaims==0 || attestor==address(0)) revert InvalidAttestor();
        ruleAttestors[ruleId][attestor]=allowed;
        emit AttestorChanged(ruleId,attestor,allowed);
    }

    /// @notice Governance rotates source authority and invalidates older approvals by incrementing epoch.
    /// @dev Default-deny: unconfigured rules cannot submit XP.
    function configureSource(bytes32 ruleId,bytes32 sourceId,address issuer,bool active) external onlyOwner {
        if(rules[ruleId].maxClaims==0 || sourceId==bytes32(0) || issuer==address(0)) revert InvalidSource();
        SourceConfig storage cfg=ruleSources[ruleId];
        if(cfg.epoch==type(uint64).max) revert InvalidSource();
        cfg.epoch+=1;
        cfg.sourceId=sourceId;
        cfg.issuer=issuer;
        cfg.active=active;
        emit SourceConfigured(ruleId,sourceId,issuer,cfg.epoch,active);
    }

    function sourceDigest(Proof calldata proof) public view returns(bytes32) {
        SourceConfig memory cfg=ruleSources[proof.ruleId];
        return _hashTypedDataV4(keccak256(abi.encode(
            SOURCE_TYPEHASH,cfg.sourceId,proof.recipient,proof.ruleId,proof.eventId,
            proof.evidenceDigest,proof.nonce,proof.issuedAt,proof.validUntil,cfg.epoch
        )));
    }

    function proofDigest(Proof calldata proof) public view returns(bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(
            PROOF_TYPEHASH,proof.recipient,proof.ruleId,proof.eventId,
            proof.evidenceDigest,proof.nonce,proof.issuedAt,proof.validUntil
        )));
    }

    /// @dev Caller is verifier. Attestor MUST be a separately allowed signer.
    function _verifySource(Proof calldata proof,address attestor,bytes calldata sourceSignature) private view returns(bytes32 approval) {
        SourceConfig memory source=ruleSources[proof.ruleId];
        if(!source.active || source.issuer==address(0) || source.issuer==attestor || source.issuer==msg.sender) revert InvalidSource();
        approval=sourceDigest(proof);
        if(sourceApprovalsUsed[approval] ||
           !SignatureChecker.isValidSignatureNow(source.issuer,approval,sourceSignature)) revert InvalidSource();
    }

    function _verifyClaim(Proof calldata proof,address attestor,bytes calldata signature) private view returns(bytes32 digest,uint16 amount,uint32 maxClaims) {
        if(paused) revert Paused();
        Rule memory rule=rules[proof.ruleId];
        if(!rule.active) revert InvalidRule();
        if(verifierRoles[msg.sender] < (rule.amount>=HIGH_TRUST_FROM ? 2 : 1)) revert NotVerifier();
        if(attestor==msg.sender || !ruleAttestors[proof.ruleId][attestor]) revert InvalidAttestor();
        if(proof.recipient==address(0)||proof.eventId==bytes32(0)||proof.evidenceDigest==bytes32(0)) revert InvalidProof();
        if(proof.issuedAt>block.timestamp || proof.validUntil<block.timestamp || proof.validUntil<=proof.issuedAt) revert ProofExpired();
        if(!pie.getIdentity(proof.recipient).exists) revert InvalidIdentity();
        digest=proofDigest(proof);
        if(!SignatureChecker.isValidSignatureNow(attestor,digest,signature)) revert InvalidProof();
        amount=rule.amount;
        maxClaims=rule.maxClaims;
    }

    function _consumeReplay(Proof calldata proof,address attestor,bytes32 sourceApproval) private {
        bytes32 eventKey=keccak256(abi.encode(proof.eventId));
        bytes32 evidenceKey=keccak256(abi.encode(proof.evidenceDigest));
        bytes32 nonceKey=keccak256(abi.encode(attestor,proof.nonce));
        if(usedEvents[eventKey]||usedEvidence[evidenceKey]||usedProofNonces[nonceKey]) revert Replay();
        sourceApprovalsUsed[sourceApproval]=true;
        usedEvents[eventKey]=true;
        usedEvidence[evidenceKey]=true;
        usedProofNonces[nonceKey]=true;
    }

    function submit(Proof calldata proof,address attestor,bytes calldata signature,bytes calldata sourceSignature) external returns(bytes32 claimId) {
        bytes32 approval=_verifySource(proof,attestor,sourceSignature);
        (bytes32 digest,uint16 amount,uint32 maxClaims)=_verifyClaim(proof,attestor,signature);
        claimId=keccak256(abi.encode(digest,attestor));
        if(grants[claimId].status!=Status.NONE) revert Replay();
        _reserveQuota(proof.recipient,proof.ruleId,amount,maxClaims);
        _consumeReplay(proof,attestor,approval);
        uint64 deadline=uint64(block.timestamp+CHALLENGE_PERIOD);
        grants[claimId]=Grant(proof.recipient,proof.ruleId,amount,deadline,msg.sender,attestor,Status.PENDING);
        grantSourceEpoch[claimId]=ruleSources[proof.ruleId].epoch;
        emit GrantPending(claimId,proof.recipient,attestor,amount,deadline);
    }

    /// @dev Isolated quota reservation reduces submit() stack pressure.
    ///      All writes revert atomically if later validation or grant storage fails.
    function _reserveQuota(address recipient,bytes32 ruleId,uint16 amount,uint32 maxClaims) private {
        uint32 count=claimsPerRule[recipient][ruleId];
        uint256 dayId=block.timestamp / 1 days;
        uint256 weekId=block.timestamp / 7 days;
        if(count>=maxClaims ||
           uint256(dailyXP[recipient][dayId])+amount>DAILY_CAP ||
           uint256(weeklyXP[recipient][weekId])+amount>WEEKLY_CAP) revert LimitReached();

        claimsPerRule[recipient][ruleId]=count+1;
        dailyXP[recipient][dayId]+=amount;
        weeklyXP[recipient][weekId]+=amount;
    }

    function finalize(bytes32 claimId) external {
        if(paused) revert Paused();
        Grant storage grant=grants[claimId];
        if(grant.status!=Status.PENDING) revert BadGrantStatus();
        SourceConfig memory source=ruleSources[grant.ruleId];
        if(!source.active || source.epoch!=grantSourceEpoch[claimId]) revert InvalidSource();
        if(block.timestamp<grant.finalizesAt) revert TooEarly();
        grant.status=Status.VALID;
        validEarnedXP[grant.recipient]+=grant.amount;
        emit GrantFinalized(claimId,grant.recipient,grant.amount);
    }

    /// @notice High-privilege correction; governance must document reason and appeal off-chain.
    function revoke(bytes32 claimId,bytes32 reason) external onlyOwner {
        Grant storage grant=grants[claimId];
        if(grant.status!=Status.PENDING && grant.status!=Status.VALID) revert BadGrantStatus();
        if(reason==bytes32(0)) revert InvalidProof();
        if(grant.status==Status.VALID) validEarnedXP[grant.recipient]-=grant.amount;
        grant.status=Status.REVOKED;
        emit GrantRevoked(claimId,grant.recipient,grant.amount,reason);
    }

    /// @notice ABI-compatible with fresh TrustedXPSourceRegistryV02, which checks policy owner and core.
    function totalXP(address wallet) external view returns(uint64) {
        IPIEForVerifiedXP.Identity memory identity=pie.getIdentity(wallet);
        if(!identity.exists) return 0;
        return identity.xp+validEarnedXP[wallet];
    }
}
