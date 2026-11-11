import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import IssuerVerificationSection from "../../../../../components/Home/VerificationSection/Result/IssuerVerificationSection";
import { IssuerVerificationResult } from "../../../../../types/data-types";

// Return the key (or the provided default) so assertions do not depend on locale files.
jest.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, opts?: { defaultValue?: string }) => key ?? opts?.defaultValue,
  }),
}));

const trusted: IssuerVerificationResult = {
  overallStatus: "TRUSTED",
  displayStatus: "TRUSTED_ISSUER",
  issuerName: "Example Authority",
  organizationType: "Government",
  jurisdiction: "IN",
  checks: [
    { id: "ISSUER_IDENTIFIER_VALID", status: "PASS", message: "Identifier is well formed." },
    { id: "ISSUER_ACTIVE", status: "FAIL", message: "Issuer is not active." },
  ],
};

describe("IssuerVerificationSection", () => {
  it("renders nothing when no issuer verification is present", () => {
    const { container } = render(<IssuerVerificationSection issuerVerification={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("shows status and issuer details", () => {
    render(<IssuerVerificationSection issuerVerification={trusted} />);
    expect(screen.getByTestId("issuer-status-badge")).toHaveTextContent("status.TRUSTED");
    expect(screen.getByTestId("issuer-display-status")).toHaveTextContent("display.TRUSTED_ISSUER");
    expect(screen.getByText("Example Authority")).toBeInTheDocument();
    expect(screen.getByText("IN")).toBeInTheDocument();
  });

  it("keeps checks collapsed until expanded", () => {
    render(<IssuerVerificationSection issuerVerification={trusted} />);
    expect(screen.queryByTestId("issuer-check-ISSUER_ACTIVE")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "showChecks" }));

    expect(screen.getByTestId("issuer-check-ISSUER_ACTIVE")).toHaveTextContent("Issuer is not active.");
    expect(screen.getByRole("button", { name: "hideChecks" })).toHaveAttribute("aria-expanded", "true");
  });

  it("explains that INCONCLUSIVE is not an accusation", () => {
    render(<IssuerVerificationSection issuerVerification={{ overallStatus: "INCONCLUSIVE", displayStatus: "VERIFICATION_INCONCLUSIVE" }} />);
    expect(screen.getByTestId("issuer-inconclusive-note")).toBeInTheDocument();
  });

  it("does not show a note or checks button for UNTRUSTED without checks", () => {
    render(<IssuerVerificationSection issuerVerification={{ overallStatus: "UNTRUSTED", displayStatus: "ISSUER_REVOKED" }} />);
    expect(screen.queryByTestId("issuer-inconclusive-note")).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
