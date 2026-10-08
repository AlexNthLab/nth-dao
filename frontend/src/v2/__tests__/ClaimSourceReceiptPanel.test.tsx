// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../api", async (importOriginal) => ({
  ...await importOriginal<typeof import("../api")>(),
  getPortableClaimCompletionProof: vi.fn(),
  getClaimSourceReceiptStatus: vi.fn(),
  importClaimSourceReceipt: vi.fn(),
  reconcileClaimSourceReceipt: vi.fn(),
}));

import {
  ApiHttpError,
  getPortableClaimCompletionProof,
  getClaimSourceReceiptStatus,
  importClaimSourceReceipt,
  reconcileClaimSourceReceipt,
} from "../api";
import { ClaimSourceReceiptPanel } from "../components/ClaimSourceReceiptPanel";

const nonce = "n".repeat(24);
const head = `sha256:${"a".repeat(64)}`;
const sourceClaimId = "b".repeat(64);
const responseDigest = `sha256:${"c".repeat(64)}`;
const sourceDid = "did:key:zSource";
const claimantDid = "did:key:zClaimant";

const props = { nonce, head, sourceClaimId, sourceDid, claimantDid };
const pending = {
  source_claim_id: sourceClaimId, completion_head_digest: head,
  expected_response_digest: responseDigest, receipt_verified: true,
  pending: true, observed_locally: false, local_observation_event_id: null,
  accepted: false, settled: false,
} as const;
const observed = {
  ...pending, pending: false, observed_locally: true,
  local_observation_event_id: "d".repeat(64),
} as const;
const importResult = {
  source_claim_id: sourceClaimId, completion_head_digest: head,
  source_did: sourceDid, claimant_did: claimantDid,
  observed_locally: true,
} as const;
const portableProof = {
  kind: "nth-market-claim-completion-proof", version: 1, nonce,
  source_claim_id: sourceClaimId,
  announcement: {}, intent: { nonce }, claim_receipt: {},
  authority_ack: { ack_id: sourceClaimId },
  completion_chain: [{ completion_record: { version: 1 } }],
};
const rawProof = JSON.stringify({
  ...portableProof, announcement: { reward_minor: "SIGNED_INTEGER" },
}).replace('"SIGNED_INTEGER"', "9007199254740993");

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("ClaimSourceReceiptPanel", () => {
  it("downloads only the selected completion proof after an explicit click", async () => {
    vi.mocked(getPortableClaimCompletionProof).mockResolvedValue(rawProof);
    const createObjectURL = vi.fn((_blob: Blob) => "blob:completion-proof");
    const revokeObjectURL = vi.fn();
    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    vi.stubGlobal("URL", Object.assign(class extends URL {}, {
      createObjectURL, revokeObjectURL,
    }));
    let downloadedName = "";
    let downloadCount = 0;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloadCount += 1;
      downloadedName = this.download;
      expect(this.href).toBe("blob:completion-proof");
    });
    render(<ClaimSourceReceiptPanel {...props} />);
    expect(getPortableClaimCompletionProof).not.toHaveBeenCalled();
    expect(screen.getByText(/scoped capability token and participant metadata/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Download proof" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
    const exportedBlob = createObjectURL.mock.calls[0][0];
    const exportedText = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result));
      reader.onerror = () => reject(reader.error);
      reader.readAsText(exportedBlob);
    });
    expect(exportedText).toBe(rawProof);
    expect(getPortableClaimCompletionProof).toHaveBeenCalledWith(
      nonce, head, sourceClaimId, expect.any(AbortSignal),
    );
    expect(downloadedName).toContain(sourceClaimId.slice(0, 12));
    expect(downloadedName).toContain(head.slice(7, 19));
    expect(screen.getByText(/Download requested/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Download proof" }));
    await waitFor(() => expect(downloadCount).toBe(2));
    expect(getPortableClaimCompletionProof).toHaveBeenCalledTimes(2);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const releaseIndex = timeoutSpy.mock.calls.findIndex(([, delay]) => delay === 60_000);
    expect(releaseIndex).toBeGreaterThanOrEqual(0);
    expect(revokeObjectURL).not.toHaveBeenCalled();
    const release = timeoutSpy.mock.calls[releaseIndex][0] as () => void;
    release();
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:completion-proof");
    clearTimeout(timeoutSpy.mock.results[releaseIndex].value as ReturnType<typeof setTimeout>);
  });

  it("refuses changed bytes for a previously exported signed head", async () => {
    vi.mocked(getPortableClaimCompletionProof)
      .mockResolvedValueOnce(rawProof)
      .mockResolvedValueOnce(rawProof.replace('"version":1', '"version":2'));
    const createObjectURL = vi.fn(() => "blob:completion-proof");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(class extends URL {}, {
      createObjectURL, revokeObjectURL,
    }));
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    const timeoutSpy = vi.spyOn(globalThis, "setTimeout");
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Download proof" }));
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Download proof" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("changed for the same head"),
    );
    expect(click).toHaveBeenCalledTimes(1);
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    const releaseIndex = timeoutSpy.mock.calls.findIndex(([, delay]) => delay === 60_000);
    clearTimeout(timeoutSpy.mock.results[releaseIndex].value as ReturnType<typeof setTimeout>);
  });

  it("does not create a download when the local proof export is rejected", async () => {
    vi.mocked(getPortableClaimCompletionProof).mockRejectedValueOnce(
      new ApiHttpError("GET", "/completion/proof", 503),
    );
    const createObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(class extends URL {}, { createObjectURL }));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Download proof" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("HTTP 503"),
    ));
    expect(createObjectURL).not.toHaveBeenCalled();
    expect(screen.queryByText(/Download requested/)).toBeNull();
  });

  it("labels a verified source observation as a statement, not acceptance", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(observed);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(screen.getByText(/Not work acceptance or payment/)).toBeTruthy();
    expect(getClaimSourceReceiptStatus).toHaveBeenCalledWith(nonce, head, expect.any(AbortSignal));
  });

  it("recovers only the verified pending digest after explicit action", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending).mockResolvedValueOnce(observed);
    vi.mocked(reconcileClaimSourceReceipt).mockResolvedValueOnce({
      ...importResult, response_digest: responseDigest,
    } as Awaited<ReturnType<typeof reconcileClaimSourceReceipt>>);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    expect(screen.getByText(responseDigest)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reconcile retained receipt" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(reconcileClaimSourceReceipt).toHaveBeenCalledWith(
      nonce, head, sourceClaimId, responseDigest, expect.any(AbortSignal),
    );
  });

  it("rejects malformed or wrong-head input before sending it", async () => {
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    const input = screen.getByRole("textbox", { name: "Signed source receipt JSON" });
    fireEvent.change(input, { target: { value: "{" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("Invalid source receipt JSON"),
    );
    fireEvent.change(input, { target: { value: JSON.stringify({
      payload: { source_claim_id: sourceClaimId,
        completion_head_digest: `sha256:${"f".repeat(64)}` },
    }) } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("does not match this completion"),
    );
    expect(importClaimSourceReceipt).not.toHaveBeenCalled();
  });

  it("imports matching evidence, clears the input, and rechecks stored state", async () => {
    vi.mocked(importClaimSourceReceipt).mockResolvedValueOnce(
      importResult as Awaited<ReturnType<typeof importClaimSourceReceipt>>,
    );
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(observed);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    const input = screen.getByRole("textbox", { name: "Signed source receipt JSON" });
    const signed = { source_receipt_event: {
      payload: { source_claim_id: sourceClaimId, completion_head_digest: head },
    } };
    fireEvent.change(input, { target: { value: JSON.stringify(signed) } });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(importClaimSourceReceipt).toHaveBeenCalledWith(
      nonce, head, sourceClaimId, JSON.stringify(signed), expect.any(AbortSignal),
    );
    expect(screen.queryByRole("textbox", { name: "Signed source receipt JSON" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    expect(screen.getByRole("textbox", { name: "Signed source receipt JSON" }))
      .toHaveProperty("value", "");
  });

  it("uses the server's claim pin when a legacy UI record lacks source DID", async () => {
    vi.mocked(importClaimSourceReceipt).mockResolvedValueOnce(
      importResult as Awaited<ReturnType<typeof importClaimSourceReceipt>>,
    );
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(observed);
    render(<ClaimSourceReceiptPanel {...props} sourceDid="" />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("shows retained-pending recovery after an uncertain import failure", async () => {
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(new Error("HTTP 503"));
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending).mockResolvedValueOnce(pending);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    await waitFor(() => expect(screen.getByText("Verified file awaits local audit")).toBeTruthy());
    expect(screen.getByRole("button", { name: "Reconcile retained receipt" }))
      .toHaveProperty("disabled", true);
    expect(screen.getByText(/may predate this import/)).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Reconcile retained receipt" }))
      .toHaveProperty("disabled", false));
  });

  it("does not report failure when a lost import response has an observed receipt", async () => {
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(new Error("connection lost"));
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(observed);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText(/submission outcome is uncertain/i)).toBeTruthy();
  });

  it("clears a stale pending label when recovery cannot reverify the file", async () => {
    vi.mocked(getClaimSourceReceiptStatus)
      .mockResolvedValueOnce(pending).mockRejectedValueOnce(new Error("disk unavailable"));
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(new Error("connection lost"));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("outcome unknown"),
    ));
    expect(screen.queryByText("Verified file awaits local audit")).toBeNull();
  });

  it("rechecks a lost reconciliation response before showing success", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending).mockResolvedValueOnce(observed);
    vi.mocked(reconcileClaimSourceReceipt).mockRejectedValueOnce(new Error("connection lost"));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reconcile retained receipt" }));
    expect(await screen.findByText("Source statement observed locally")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps a definite import rejection and withdraws an older pending status", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending);
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(
      new ApiHttpError("POST", "/source-receipt", 422),
    );
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("HTTP 422"),
    ));
    expect(screen.queryByText("Verified file awaits local audit")).toBeNull();
    expect(getClaimSourceReceiptStatus).toHaveBeenCalledTimes(1);
  });

  it("does not turn a conflicting import into success for an older retained receipt", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending);
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(
      new ApiHttpError("POST", "/source-receipt", 409),
    );
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("HTTP 409"),
    ));
    expect(screen.queryByText("Verified file awaits local audit")).toBeNull();
    expect(screen.queryByRole("button", { name: "Reconcile retained receipt" })).toBeNull();
    expect(getClaimSourceReceiptStatus).toHaveBeenCalledTimes(1);
  });

  it("treats a rate-limited import as uncertain and rechecks local evidence", async () => {
    vi.mocked(importClaimSourceReceipt).mockRejectedValueOnce(
      new ApiHttpError("POST", "/source-receipt", 429),
    );
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("does not treat a changed retained digest as reconciliation success", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending)
      .mockResolvedValueOnce({ ...observed, expected_response_digest: `sha256:${"f".repeat(64)}` });
    vi.mocked(reconcileClaimSourceReceipt).mockRejectedValueOnce(new Error("connection lost"));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reconcile retained receipt" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("outcome unknown"),
    ));
    expect(screen.queryByText("Source statement observed locally")).toBeNull();
  });

  it("releases the controls when an import never responds", async () => {
    vi.useFakeTimers();
    vi.mocked(importClaimSourceReceipt).mockImplementationOnce(() => new Promise(() => {}));
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(null);
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    expect(screen.getByRole("button", { name: "Verifying…" })).toHaveProperty("disabled", true);
    await act(async () => { await vi.advanceTimersByTimeAsync(30_001); });
    expect(screen.getByRole("button", { name: "Verify and retain" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("outcome unknown"),
    );
  });

  it("does not probe local evidence after unmounting a hung import", async () => {
    vi.useFakeTimers();
    vi.mocked(importClaimSourceReceipt).mockImplementationOnce(() => new Promise(() => {}));
    const view = render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Signed source receipt JSON" }), {
      target: { value: JSON.stringify({ payload: {
        source_claim_id: sourceClaimId, completion_head_digest: head,
      } }) },
    });
    fireEvent.click(screen.getByRole("button", { name: "Verify and retain" }));
    view.unmount();
    await act(async () => { await vi.advanceTimersByTimeAsync(30_001); });
    expect(getClaimSourceReceiptStatus).not.toHaveBeenCalled();
  });

  it("releases the controls when a status check never responds", async () => {
    vi.useFakeTimers();
    vi.mocked(getClaimSourceReceiptStatus).mockImplementationOnce(() => new Promise(() => {}));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_001); });
    expect(screen.getByRole("button", { name: "Check source receipt" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("check timed out"),
    );
  });

  it("releases the controls when reconciliation never responds", async () => {
    vi.mocked(getClaimSourceReceiptStatus).mockResolvedValueOnce(pending);
    vi.mocked(reconcileClaimSourceReceipt).mockImplementationOnce(() => new Promise(() => {}));
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    expect(await screen.findByText("Verified file awaits local audit")).toBeTruthy();
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Reconcile retained receipt" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_001); });
    expect(screen.getByRole("button", { name: "Check source receipt" }))
      .toHaveProperty("disabled", false);
    expect(screen.queryByRole("button", { name: "Reconcile retained receipt" })).toBeNull();
    expect(screen.getByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("outcome unknown"),
    );
  });

  it("reads a small JSON file but rejects an oversized one before import", async () => {
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    const input = screen.getByLabelText("Choose source receipt JSON");
    const file = new File(["{}"], "receipt.json", { type: "application/json" });
    Object.defineProperty(file, "text", { value: async () => "{}" });
    fireEvent.change(input, { target: { files: [file] } });
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Signed source receipt JSON" }))
      .toHaveProperty("value", "{}"));
    const huge = new File(["x"], "huge.json", { type: "application/json" });
    Object.defineProperty(huge, "size", { value: 2_000_000 });
    fireEvent.change(input, { target: { files: [huge] } });
    expect(await screen.findByRole("alert")).toHaveProperty(
      "textContent", expect.stringContaining("size limit"),
    );
    expect(screen.getByRole("textbox", { name: "Signed source receipt JSON" }))
      .toHaveProperty("value", "");
    expect(screen.getByRole("button", { name: "Verify and retain" }))
      .toHaveProperty("disabled", true);
    expect(importClaimSourceReceipt).not.toHaveBeenCalled();
  });

  it("does not let an older file read replace a newer selection", async () => {
    render(<ClaimSourceReceiptPanel {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Import source receipt" }));
    const input = screen.getByLabelText("Choose source receipt JSON");
    let finishFirst!: (value: string) => void;
    const first = new File(["{}"], "first.json", { type: "application/json" });
    Object.defineProperty(first, "text", { value: () => new Promise<string>((resolve) => {
      finishFirst = resolve;
    }) });
    const second = new File(["{}"], "second.json", { type: "application/json" });
    Object.defineProperty(second, "text", { value: async () => '{"new":true}' });
    fireEvent.change(input, { target: { files: [first] } });
    fireEvent.change(input, { target: { files: [second] } });
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Signed source receipt JSON" }))
      .toHaveProperty("value", '{"new":true}'));
    finishFirst('{"old":true}');
    await waitFor(() => expect(screen.getByRole("textbox", { name: "Signed source receipt JSON" }))
      .toHaveProperty("value", '{"new":true}'));
  });
});
