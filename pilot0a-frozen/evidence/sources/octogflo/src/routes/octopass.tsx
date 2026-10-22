import { createFileRoute } from "@tanstack/react-router";
import { ArrowRight, Ban } from "lucide-react";
import { PageHeader } from "@/components/Shell";
import { useT } from "@/i18n/i18n";
import { pageMeta } from "@/lib/meta";

export const Route = createFileRoute("/octopass")({
  head: () =>
    pageMeta(
      "OctoPass Local (concept)",
      "Future opt-in, user-controlled off-chain profile layer, separate from PIE protocol identity. Not available in MVP 01.",
    ),
  component: OctoPass,
});

function OctoPass() {
  const t = useT();
  return (
    <div>
      <PageHeader
        title={t("op.title")}
        sub={t("op.sub")}
        badge={
          <span className="rounded border border-warning px-2 py-0.5 font-mono text-[10px] font-bold text-warning">
            {t("op.status")}
          </span>
        }
      />
      <h2 className="mb-3 text-xl font-semibold">{t("op.compare")}</h2>
      <div className="mb-4 grid items-stretch gap-4 md:grid-cols-[1fr_auto_1fr]">
        <div className="panel border-primary p-5">
          <p className="font-semibold text-primary">{t("op.pieTitle")}</p>
          <ul className="mt-3 space-y-1 text-sm">
            {(["op.pie1", "op.pie2", "op.pie3", "op.pie4"] as const).map((k) => (
              <li key={k}>• {t(k)}</li>
            ))}
          </ul>
        </div>
        <p className="flex items-center justify-center gap-1 text-center text-xs text-muted-foreground">
          <ArrowRight className="h-4 w-4 rotate-90 md:rotate-0" aria-hidden="true" />{" "}
          {t("op.readonly")}
        </p>
        <div className="panel border-accent p-5">
          <p className="font-semibold text-accent">{t("op.passTitle")}</p>
          <ul className="mt-3 space-y-1 text-sm">
            {(["op.pass1", "op.pass2", "op.pass3", "op.pass4"] as const).map((k) => (
              <li key={k}>• {t(k)}</li>
            ))}
          </ul>
        </div>
      </div>
      <p className="mb-8 rounded-md border border-destructive p-4 text-sm text-destructive">
        {t("op.noXp")}
      </p>
      <div className="panel mb-8 grid items-center gap-4 p-6 md:grid-cols-[1fr_auto_1fr]">
        <div className="rounded-lg border border-accent p-4 text-center">
          <p className="font-semibold text-accent">{t("op.profile")}</p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">profile_id: DEMO-OP-001</p>
        </div>
        <p className="text-center text-xs text-muted-foreground">⇠ {t("op.link")} ⇢</p>
        <div className="rounded-lg border border-primary p-4 text-center">
          <p className="font-semibold text-primary">{t("op.protocol")}</p>
          <p className="mt-1 font-mono text-xs text-muted-foreground">protocol_id: DEMO-PIE-0xA1</p>
        </div>
      </div>
      <div className="grid gap-4 md:grid-cols-2">
        <ul className="panel space-y-3 p-5 text-sm">
          {(["op.p1", "op.p2", "op.p3", "op.p4"] as const).map((k) => (
            <li key={k}>• {t(k)}</li>
          ))}
        </ul>
        <div className="panel p-5">
          <h2 className="font-semibold text-destructive">{t("op.never")}</h2>
          <ul className="mt-3 space-y-3 text-sm">
            {(["op.n1", "op.n2", "op.n3"] as const).map((k) => (
              <li key={k} className="flex gap-2">
                <Ban className="h-4 w-4 shrink-0 text-destructive" /> {t(k)}
              </li>
            ))}
          </ul>
        </div>
      </div>
      <section className="panel mt-8 p-5">
        <h2 className="font-semibold">{t("op.adapters")}</h2>
        <ul className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          {(
            [
              "op.ad.wallet",
              "op.ad.consent",
              "op.ad.ids",
              "op.ad.privacy",
              "op.ad.revoke",
              "op.ad.read",
            ] as const
          ).map((k) => (
            <li key={k} className="flex items-center justify-between gap-2 rounded border p-2">
              {t(k)} <span className="font-mono text-[10px] text-warning">FUTURE</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
