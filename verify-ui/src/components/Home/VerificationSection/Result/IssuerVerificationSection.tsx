import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { IssuerVerificationResult } from "../../../../types/data-types";

const overallStyles: Record<string, string> = {
  TRUSTED: "bg-successText",
  UNTRUSTED: "bg-invalidText",
  INCONCLUSIVE: "bg-expiredText",
};

const checkSymbol: Record<string, string> = {
  PASS: "✓",
  FAIL: "✕",
  INCONCLUSIVE: "?",
  NOT_EVALUATED: "–",
  NOT_APPLICABLE: "–",
};

/**
 * Shows the outcome of server-side issuer verification. Renders nothing when the server did not return an
 * issuerVerification block (feature disabled or not requested), so existing results look unchanged.
 * Only the server's user-facing message is shown for each check; resolver and registry internals are never displayed.
 */
const IssuerVerificationSection = ({ issuerVerification }: { issuerVerification?: IssuerVerificationResult | null }) => {
  const { t } = useTranslation("IssuerVerification");
  const [expanded, setExpanded] = useState(false);

  if (!issuerVerification || !issuerVerification.overallStatus) return null;

  const status = issuerVerification.overallStatus;
  const displayKey = issuerVerification.displayStatus ?? status;
  const name = issuerVerification.issuerName ?? issuerVerification.legalName;
  const checks = issuerVerification.checks ?? [];

  return (
    <div id="issuer-verification-section" className="mx-auto mt-4 w-full max-w-[600px] rounded-lg border border-gray-200 bg-white p-4">
      <h3 className="mb-2 text-lg font-semibold">{t("title")}</h3>
      <div className="flex items-center gap-3">
        <span
          data-testid="issuer-status-badge"
          className={`rounded-full px-3 py-1 text-sm text-white ${overallStyles[status] ?? "bg-expiredText"}`}
        >
          {t(`status.${status}`, { defaultValue: status })}
        </span>
        <span data-testid="issuer-display-status" className="text-sm">
          {t(`display.${displayKey}`, { defaultValue: t(`status.${status}`, { defaultValue: status }) })}
        </span>
      </div>
      {status === "INCONCLUSIVE" && (
        <p className="mt-2 text-sm" data-testid="issuer-inconclusive-note">
          {t("inconclusiveNote")}
        </p>
      )}
      {name && (
        <dl className="mt-3 grid grid-cols-[auto,1fr] gap-x-3 gap-y-1 text-sm">
          <dt className="font-medium">{t("issuer")}</dt>
          <dd>{name}</dd>
          {issuerVerification.organizationType && (
            <>
              <dt className="font-medium">{t("organizationType")}</dt>
              <dd>{issuerVerification.organizationType}</dd>
            </>
          )}
          {issuerVerification.jurisdiction && (
            <>
              <dt className="font-medium">{t("jurisdiction")}</dt>
              <dd>{issuerVerification.jurisdiction}</dd>
            </>
          )}
        </dl>
      )}
      {checks.length > 0 && (
        <>
          <button
            type="button"
            className="mt-3 text-sm underline"
            aria-expanded={expanded}
            aria-controls="issuer-checks-list"
            onClick={() => setExpanded((v) => !v)}
          >
            {expanded ? t("hideChecks") : t("showChecks")}
          </button>
          {expanded && (
            <ul id="issuer-checks-list" className="mt-2 space-y-1 text-sm">
              {checks.map((c) => (
                <li key={c.id} data-testid={`issuer-check-${c.id}`} className="flex gap-2">
                  <span aria-label={t(`checkStatus.${c.status}`, { defaultValue: c.status })}>{checkSymbol[c.status] ?? "?"}</span>
                  <span>
                    <span className="font-medium">{t(`checks.${c.id}`, { defaultValue: c.id })}</span>
                    {c.message ? <span className="block text-gray-600">{c.message}</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </div>
  );
};

export default IssuerVerificationSection;
