import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

import { ResourceProfilesPanel } from "../components/ResourceProfilesPanel";
import { ToastProvider } from "../components/Toast";
import {
  importResourceProfile,
  listResourceProfiles,
  setResourceProfileRecognition,
} from "../api";


vi.mock("../api", () => ({
  listResourceProfiles: vi.fn(),
  importResourceProfile: vi.fn(),
  setResourceProfileRecognition: vi.fn(),
}));


const digest = `sha256:${"a".repeat(64)}`;
const profile = {
  digest,
  profile_id: "community.book",
  version: "1.0.0",
  publisher_did: "did:key:z6Mktestpublisher",
  summary: "A signed book profile",
  resource_types: ["book"],
  category_mappings: [{
    community_category: "books/print",
    market_category: "products" as const,
  }],
  schema: {
    type: "object" as const,
    properties: {
      title: {
        type: "string" as const,
        required: true,
        description: "Book title.",
        enum: [],
      },
    },
    additional_properties: false,
  },
  published_at: "2026-08-08T00:00:00Z",
  not_after: "2027-08-08T00:00:00Z",
  active: true,
  active_reason: "active",
  recognized: false,
  signature_verified: true as const,
  execution_authority_granted: false as const,
};


function renderPanel() {
  return render(
    <ToastProvider>
      <ResourceProfilesPanel />
    </ToastProvider>,
  );
}


describe("ResourceProfilesPanel", () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.mocked(listResourceProfiles).mockResolvedValue({
      items: [profile],
      count: 1,
      returned: 1,
      next_cursor: "",
      truncated: false,
      warning: "Signature verification proves provenance only.",
    });
    vi.mocked(importResourceProfile).mockResolvedValue({
      profile,
      installed: true,
      audit_event_id: "event-import",
      audit_created: true,
    });
    vi.mocked(setResourceProfileRecognition).mockResolvedValue({
      profile: { ...profile, recognized: true },
      changed: true,
      operation_id: "operation-recognize",
      audit_event_id: "event-recognize",
      audit_created: true,
    });
  });

  afterEach(() => {
    cleanup();
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  it("labels a signed but unrecognized profile without granting authority", async () => {
    renderPanel();

    expect(await screen.findByText("community.book")).toBeTruthy();
    expect(screen.getByText("Verified only")).toBeTruthy();
    expect(screen.getByText("Signature verification proves provenance only.")).toBeTruthy();
    expect(screen.queryByText(/execution authority granted/i)).toBeNull();
  });

  it("uses a fresh idempotency key when recognizing a profile", async () => {
    renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Recognize" }));

    await waitFor(() => {
      expect(setResourceProfileRecognition).toHaveBeenCalledWith(
        digest,
        true,
        expect.stringMatching(/^profile-recognition:[0-9a-f-]{36}$/),
      );
    });
  });

  it("reuses the same idempotency key after an incomplete request", async () => {
    vi.mocked(setResourceProfileRecognition)
      .mockRejectedValueOnce(new Error("completion audit is incomplete"))
      .mockResolvedValueOnce({
        profile: { ...profile, recognized: true },
        changed: false,
        operation_id: "operation-retry",
        audit_event_id: "event-retry",
        audit_created: true,
      });
    renderPanel();
    const button = await screen.findByRole("button", { name: "Recognize" });

    fireEvent.click(button);
    await screen.findByRole("alert");
    await waitFor(() => expect(button.hasAttribute("disabled")).toBe(false));
    fireEvent.click(button);

    await waitFor(() => expect(setResourceProfileRecognition).toHaveBeenCalledTimes(2));
    const firstKey = vi.mocked(setResourceProfileRecognition).mock.calls[0][2];
    const secondKey = vi.mocked(setResourceProfileRecognition).mock.calls[1][2];
    expect(secondKey).toBe(firstKey);
  });

  it("retires a pending key when refreshed policy already reached its target", async () => {
    vi.mocked(setResourceProfileRecognition).mockRejectedValueOnce(
      new Error("response was lost"),
    );
    const rendered = renderPanel();
    fireEvent.click(await screen.findByRole("button", { name: "Recognize" }));
    await screen.findByRole("alert");
    expect(sessionStorage.length).toBe(1);
    rendered.unmount();

    vi.mocked(listResourceProfiles).mockResolvedValue({
      items: [{ ...profile, recognized: true }],
      count: 1,
      returned: 1,
      next_cursor: "",
      truncated: false,
      warning: "Signature verification proves provenance only.",
    });
    renderPanel();
    await screen.findByText("Recognized locally");

    expect(sessionStorage.length).toBe(0);
  });

  it("rejects malformed local JSON before calling the backend", async () => {
    renderPanel();
    fireEvent.change(screen.getByLabelText("Signed Resource Profile JSON"), {
      target: { value: "{broken" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and import" }));

    expect((await screen.findByRole("alert")).textContent).toContain("must be valid JSON");
    expect(importResourceProfile).not.toHaveBeenCalled();
  });

  it("submits a JSON object for backend signature verification", async () => {
    renderPanel();
    const document = { kind: "org.nthdao.resource-profile", profile_id: "community.book" };
    fireEvent.change(screen.getByLabelText("Signed Resource Profile JSON"), {
      target: { value: JSON.stringify(document) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and import" }));

    await waitFor(() => expect(importResourceProfile).toHaveBeenCalledWith(document));
  });

  it("loads the next digest page without hiding the first page", async () => {
    const second = {
      ...profile,
      digest: `sha256:${"b".repeat(64)}`,
      profile_id: "community.magazine",
    };
    vi.mocked(listResourceProfiles)
      .mockResolvedValueOnce({
        items: [profile],
        count: 2,
        returned: 1,
        next_cursor: profile.digest,
        truncated: true,
        warning: "Signature verification proves provenance only.",
      })
      .mockResolvedValueOnce({
        items: [second],
        count: 2,
        returned: 1,
        next_cursor: "",
        truncated: false,
        warning: "Signature verification proves provenance only.",
      });
    renderPanel();

    fireEvent.click(await screen.findByRole("button", { name: "Load more" }));

    expect(await screen.findByText("community.magazine")).toBeTruthy();
    expect(screen.getByText("community.book")).toBeTruthy();
    expect(screen.getByText("2 of 2 local")).toBeTruthy();
    expect(listResourceProfiles).toHaveBeenLastCalledWith(
      undefined,
      profile.digest,
      100,
    );
  });
});
