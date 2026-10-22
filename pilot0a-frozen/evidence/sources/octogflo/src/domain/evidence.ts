// Manually curated, dated snapshot of public GFLO development evidence.
// Pinned references only — never fetched live, never simulated.
export const SNAPSHOT_DATE = "21 Oct 2026";

export type PrStatus = "MERGED" | "OPEN / DRAFT / PARTIAL FIX" | "DESIGN / DRAFT";

export interface RepoRef { name: string; role: string; url: string }
export interface PrRef {
  number: number;
  title: string;
  status: PrStatus;
  url: string;
  shas: { label: string; sha: string }[];
  note: string;
}

const GH = "https://github.com/elanmust-GFLOer";

export const repos: RepoRef[] = [
  { name: "gflo-pie", role: "PIE Core / Security CI", url: `${GH}/gflo-pie` },
  { name: "GFLO.Octo_PIE-cookR", role: "Integration workspace / cookR", url: `${GH}/GFLO.Octo_PIE-cookR` },
];

export const prs: PrRef[] = [
  {
    number: 11, title: "Security baseline", status: "MERGED", url: `${GH}/gflo-pie/pull/11`,
    shas: [
      { label: "Audited head", sha: "78c3fad7a076afa73a61b0ae3e3a940abf25d699" },
      { label: "Merge commit", sha: "918af7b0080cbfe239053e792061a386615ec291" },
    ],
    note: "Merged after scoped review. Scope-limited evidence, not a production-readiness claim.",
  },
  {
    number: 12, title: "Verified Contribution Core", status: "MERGED", url: `${GH}/gflo-pie/pull/12`,
    shas: [{ label: "Merge commit", sha: "b2c6930697b367be22437d76740e9768496711f3" }],
    note: "Merged. Scoped Codex PASS and CI evidence do not equal production-readiness.",
  },
  {
    number: 13, title: "CI provenance hardening", status: "MERGED", url: `${GH}/gflo-pie/pull/13`,
    shas: [{ label: "Merge commit", sha: "a4e11cb467c2eae6f6baf2419aaa38aa653fdf16" }],
    note: "Merged. Hardens CI provenance; not an external audit.",
  },
  {
    number: 14, title: "Hardhat dependency security", status: "OPEN / DRAFT / PARTIAL FIX", url: `${GH}/gflo-pie/pull/14`,
    shas: [{ label: "Last checked head", sha: "b9eb195918b0d3d5a11b0fbf6795269bc243a084" }],
    note: "npm-targeted tmp/ws fix verified; dependency acceptance still OPEN. npm audit: 20 findings, 10 High. Not PASS, not merged.",
  },
  {
    number: 15, title: "OctoPush × OctoPass × PIE Proof Bridge", status: "DESIGN / DRAFT", url: `${GH}/gflo-pie/pull/15`,
    shas: [{ label: "Last checked head", sha: "58ab0840cd1e1fd273f7cdc0fe4e72f5b684ef95" }],
    note: "Design draft only. Not integrated anywhere.",
  },
];

export const evidenceLinks = [
  { label: "gflo-pie GitHub Actions", url: `${GH}/gflo-pie/actions` },
  { label: "Feature branch feature/pie-core-v0.2", url: `${GH}/gflo-pie/tree/feature/pie-core-v0.2` },
  { label: "Proof bridge PR #15", url: `${GH}/gflo-pie/pull/15` },
];
