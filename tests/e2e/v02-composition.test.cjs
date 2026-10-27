// Runs inside gflo-pie@feature/pie-core-v0.2 tests-v02 harness: copy to tests-v02/test/ and `npm test`.
const { expect } = require("chai");
const { ethers, network } = require("hardhat");

describe("E2E — v0.2 modules compose: identity → signed XP → burn ignition → effective tier", function () {
  it("runs the whole vertical slice and revocation caps the effective tier", async function () {
    const [owner, verifier, attestor, alice, mallory] = await ethers.getSigners();
    const f = (n) => ethers.getContractFactory(n);
    const core = await (await f("PIECoreIgnitionV01")).deploy(owner.address);
    const policy = await (await f("XPPolicyV03")).deploy(await core.getAddress(), owner.address);
    const adapter = await (await f("CanonicalXPAdapterV02")).deploy(await core.getAddress(), await policy.getAddress());
    const token = await (await f("GFLOFixedSupplyV01")).deploy(owner.address, ethers.parseEther("1000000"));
    const burn1 = ethers.parseEther("100"), burn2 = ethers.parseEther("500");
    const ignition = await (await f("GFLOIgnitionV01")).deploy(
      await core.getAddress(), await adapter.getAddress(), await token.getAddress(), burn1, burn2);
    await core.bindIgnition(await ignition.getAddress());
    const gate = await (await f("EffectiveTierGateV01")).deploy(await core.getAddress(), await adapter.getAddress());

    await core.connect(alice).createIdentity(2); // target Reformer
    await core.connect(mallory).createIdentity(2);
    expect(await adapter.totalXP(alice.address)).to.equal(25n);

    const rule = ethers.id("builder.completion.v1");
    await policy.registerRule(rule, 975, 1);
    await policy.setVerifierRole(verifier.address, 2);
    await policy.setAttestor(rule, attestor.address, true);

    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const proof = { recipient: alice.address, ruleId: rule, eventId: ethers.id("evt-1"),
      evidenceDigest: ethers.id("evidence-1"), nonce: 1n, issuedAt: now - 10, validUntil: now + 3600 };
    const domain = { name: "GFLO XP Evidence", version: "1", chainId: 31337, verifyingContract: await policy.getAddress() };
    const types = { GFLOEvidence: [
      { name: "recipient", type: "address" }, { name: "ruleId", type: "bytes32" }, { name: "eventId", type: "bytes32" },
      { name: "evidenceDigest", type: "bytes32" }, { name: "nonce", type: "uint256" },
      { name: "issuedAt", type: "uint64" }, { name: "validUntil", type: "uint64" } ] };
    const sig = await attestor.signTypedData(domain, types, proof);
    const tx = await policy.connect(verifier).submit(proof, attestor.address, sig);
    const claimId = (await tx.wait()).logs.map((l) => policy.interface.parseLog(l)).find((e) => e && e.name === "GrantPending").args.claimId;

    await expect(policy.finalize(claimId)).to.be.revertedWithCustomError(policy, "TooEarly");
    await network.provider.send("evm_increaseTime", [3 * 86400]);
    await policy.finalize(claimId);
    expect(await adapter.totalXP(alice.address)).to.equal(1000n);

    await token.transfer(alice.address, burn1);
    await token.connect(alice).approve(await ignition.getAddress(), burn1);
    await token.connect(mallory).approve(await ignition.getAddress(), burn1);
    await expect(ignition.connect(mallory).ignite()).to.be.revertedWithCustomError(ignition, "InsufficientXP");

    const supply0 = await token.totalSupply();
    await ignition.connect(alice).ignite();
    expect((await core.getIdentity(alice.address)).tier).to.equal(1n);
    expect(await token.totalSupply()).to.equal(supply0 - burn1);
    expect(await gate.effectiveTier(alice.address)).to.equal(1n);

    await policy.revoke(claimId, ethers.id("fraud"));
    expect((await core.getIdentity(alice.address)).tier).to.equal(1n); // achieved stays
    expect(await gate.effectiveTier(alice.address)).to.equal(0n);       // privilege removed
    await expect(gate.requireEffectiveTier(alice.address, 1)).to.be.revertedWithCustomError(gate, "InsufficientEffectiveTier");
  });
});
