// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
vi.mock("../api", async (importOriginal) => ({
  ...await importOriginal<typeof import("../api")>(),
  verifySourceCompletionProof: vi.fn(), recordSourceCompletionProof: vi.fn(),
  getRecordedSourceCompletion: vi.fn(),
}));
import { ApiHttpError, SourceCompletionLookupState, getRecordedSourceCompletion, recordSourceCompletionProof, verifySourceCompletionProof } from "../api";
import type { SourceCompletionRecord } from "../types-v2";
import { SourceCompletionPanel } from "../components/SourceCompletionPanel";
import recorded from "./fixtures/source-completion-response.json";

const check = {
  verified: true, reason: "ok", verification_scope: "source_claim_binding_only",
  source_claim_id: recorded.source_claim_id, completion_head_digest: recorded.completion_head_digest,
  proof_digest: recorded.proof_digest, mission_id: recorded.mission_id, outcome: "succeeded", revision: 0,
  nonce_authenticated: false, recorded: false, accepted: false, settled: false,
} as const;
const receipt = { raw: JSON.stringify(recorded), summary: recorded as SourceCompletionRecord };
const absent = () => new SourceCompletionLookupState("/source", 404, "absent");

beforeEach(() => {
  vi.mocked(verifySourceCompletionProof).mockReset().mockResolvedValue(check);
  vi.mocked(recordSourceCompletionProof).mockReset().mockResolvedValue(receipt.summary);
  vi.mocked(getRecordedSourceCompletion).mockReset().mockRejectedValue(absent());
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });

async function upload(raw = "original signed proof") {
  const file = Object.assign(new File([raw], "proof.json", { type: "application/json" }), {
    text: vi.fn().mockResolvedValue(raw),
  });
  fireEvent.change(screen.getByLabelText("Claimant proof file"), { target: { files: [file] } });
  await screen.findByText("proof.json");
  return file;
}
async function preflight() {
  await upload();
  fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
  await screen.findByText("No source receipt recorded for this proof.");
}

describe("SourceCompletionPanel", () => {
  it("requires explicit verification and record actions before exposing a receipt", async () => {
    render(<SourceCompletionPanel />);
    expect(verifySourceCompletionProof).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
    await preflight();
    expect(verifySourceCompletionProof).toHaveBeenCalledWith("original signed proof", expect.any(AbortSignal));
    expect(recordSourceCompletionProof).not.toHaveBeenCalled();
    vi.mocked(getRecordedSourceCompletion).mockResolvedValue(receipt);
    fireEvent.click(screen.getByRole("button", { name: "Record and sign receipt" }));
    await screen.findByText("Source receipt recorded and reverified.");
    expect(recordSourceCompletionProof).toHaveBeenCalledWith(
      "original signed proof", check.source_claim_id, check.completion_head_digest, check.proof_digest,
      expect.any(AbortSignal),
    );
    expect(screen.getByRole("button", { name: "Download source receipt" })).toHaveProperty("disabled", false);
    expect(screen.getByText("Receipt signer")).toBeTruthy();
    expect(screen.getByText(/Work acceptance and payment remain separate/)).toBeTruthy();
  });

  it("does not record a rejected claimant proof", async () => {
    vi.mocked(verifySourceCompletionProof).mockResolvedValue({ ...check, verified: false, reason: "invalid signature" });
    render(<SourceCompletionPanel />);
    await upload();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByText("invalid signature");
    expect(recordSourceCompletionProof).not.toHaveBeenCalled();
    expect(getRecordedSourceCompletion).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
  });

  it("blocks a duplicate write until an unknown outcome is rechecked", async () => {
    render(<SourceCompletionPanel />);
    await preflight();
    vi.mocked(recordSourceCompletionProof).mockRejectedValue(new Error("network timeout"));
    vi.mocked(getRecordedSourceCompletion).mockRejectedValue(new ApiHttpError("GET", "/source", 503));
    fireEvent.click(screen.getByRole("button", { name: "Record and sign receipt" }));
    await screen.findByText("Record outcome unknown. Check source receipt before retrying.");
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
    expect(screen.getByLabelText("Claimant proof file")).toHaveProperty("disabled", true);
    vi.mocked(getRecordedSourceCompletion).mockRejectedValue(absent());
    fireEvent.click(screen.getByRole("button", { name: "Check source receipt" }));
    await screen.findByText("No source receipt recorded for this proof.");
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", false);
    expect(recordSourceCompletionProof).toHaveBeenCalledTimes(1);
  });

  it("rejects an existing receipt for different proof bytes", async () => {
    vi.mocked(getRecordedSourceCompletion).mockResolvedValue({
      ...receipt, summary: { ...receipt.summary, proof_digest: `sha256:${"e".repeat(64)}` },
    });
    render(<SourceCompletionPanel />);
    await upload();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByText("Retained source receipt binds a different proof");
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Download source receipt" })).toHaveProperty("disabled", true);
  });

  it("shows pending evidence without misrepresenting a recorded receipt as a unique result", async () => {
    vi.mocked(getRecordedSourceCompletion).mockResolvedValue({
      ...receipt, summary: { ...receipt.summary, lineage_state: "pending_audit", lineage_heads: [],
        pending_head_digests: [`sha256:${"e".repeat(64)}`], single_retained_head_digest: null },
    });
    render(<SourceCompletionPanel />);
    await upload();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByText(/Other source evidence is pending audit or repair/);
    expect(screen.getByRole("button", { name: "Download source receipt" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
  });

  it.each([404, 409])("does not enable recording after a generic lookup HTTP %s", async (status) => {
    vi.mocked(getRecordedSourceCompletion).mockRejectedValue(new ApiHttpError("GET", "/source", status));
    render(<SourceCompletionPanel />);
    await upload();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByRole("alert");
    expect(screen.getByRole("button", { name: "Record and sign receipt" })).toHaveProperty("disabled", true);
    expect(recordSourceCompletionProof).not.toHaveBeenCalled();
  });

  it("rejects oversized files before reading their contents", () => {
    render(<SourceCompletionPanel />);
    const text = vi.fn();
    const file = { name: "large.json", size: 20 * 1024 * 1024 + 1, text };
    fireEvent.change(screen.getByLabelText("Claimant proof file"), { target: { files: [file] } });
    expect(screen.getByRole("alert").textContent).toMatch(/20 MiB size limit/);
    expect(text).not.toHaveBeenCalled();
  });

  it("discards a stale file read when another file is selected", async () => {
    render(<SourceCompletionPanel />);
    let resolveFirst!: (raw: string) => void;
    const first = { name: "old.json", size: 3, text: () => new Promise<string>((resolve) => { resolveFirst = resolve; }) };
    fireEvent.change(screen.getByLabelText("Claimant proof file"), { target: { files: [first] } });
    await upload("latest proof");
    await act(async () => { resolveFirst("stale proof"); });
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByText("No source receipt recorded for this proof.");
    expect(verifySourceCompletionProof).toHaveBeenCalledWith("latest proof", expect.any(AbortSignal));
    expect(screen.queryByText("old.json")).toBeNull();
  });

  it("times out a hung preflight and allows a fresh verification", async () => {
    vi.mocked(verifySourceCompletionProof).mockImplementationOnce(() => new Promise(() => {}));
    render(<SourceCompletionPanel />);
    await upload();
    vi.useFakeTimers();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await act(async () => { await vi.advanceTimersByTimeAsync(30_001); });
    expect(screen.getByRole("alert").textContent).toMatch(/timed out/);
    expect(vi.mocked(verifySourceCompletionProof).mock.calls[0][1]?.aborted).toBe(true);
    expect(screen.getByRole("button", { name: "Verify proof" })).toHaveProperty("disabled", false);
  });

  it("rechecks the receipt before downloading and saves the original JSON", async () => {
    vi.mocked(getRecordedSourceCompletion).mockResolvedValue(receipt);
    const createObjectURL = vi.fn((_blob: Blob) => "blob:source-receipt");
    const revokeObjectURL = vi.fn();
    vi.stubGlobal("URL", Object.assign(class extends URL {}, { createObjectURL, revokeObjectURL }));
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      expect(this.download).toMatch(/^nth-source-receipt-/);
    });
    render(<SourceCompletionPanel />);
    await upload();
    fireEvent.click(screen.getByRole("button", { name: "Verify proof" }));
    await screen.findByText("Source receipt recorded and reverified.");
    fireEvent.click(screen.getByRole("button", { name: "Download source receipt" }));
    await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1));
    expect(getRecordedSourceCompletion).toHaveBeenCalledTimes(2);
    const blob = createObjectURL.mock.calls[0][0] as Blob;
    const reader = new FileReader();
    const text = new Promise((resolve) => { reader.onload = () => resolve(reader.result); });
    reader.readAsText(blob);
    expect(await text).toBe(receipt.raw);
  });
});
