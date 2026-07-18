// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BlackboardView } from "../components/BlackboardView";
import { LangProvider } from "../i18n";

afterEach(cleanup);

describe("BlackboardView process creation", () => {
  it("keeps the create form open and restores submit state when creation fails", async () => {
    let resolveCreate!: (value: boolean) => void;
    const pendingCreate = new Promise<boolean>((resolve) => {
      resolveCreate = resolve;
    });
    const onCreate = vi.fn(() => pendingCreate);

    render(
      <LangProvider>
        <BlackboardView
          processes={[]}
          workflowOptions={["engineering"]}
          onCreate={onCreate}
        />
      </LangProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: "New process" }));
    fireEvent.change(screen.getByPlaceholderText("e.g. Refund order #4521"), {
      target: { value: "Review DID invite" },
    });

    fireEvent.click(screen.getByRole("button", { name: "Create process" }));

    await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1));
    await waitFor(() => {
      expect((screen.getByRole("button", { name: "Creating..." }) as HTMLButtonElement).disabled).toBe(true);
    });

    await act(async () => {
      resolveCreate(false);
      await pendingCreate;
    });

    await waitFor(() => {
      expect((screen.getByRole("button", { name: "Create process" }) as HTMLButtonElement).disabled).toBe(false);
    });
    expect(screen.getByText("Start a new process")).toBeTruthy();
  });
});
