import { describe, expect, it } from "vitest";
import { compareBy, distinct, listPage, matchesText } from "./listing";

interface Row {
  name: string;
  cpu: number | null;
}

const rows: Row[] = [
  { name: "svchost.exe", cpu: 1.5 },
  { name: "chrome.exe", cpu: null },
  { name: "System", cpu: 12 },
  { name: "Code.exe", cpu: 4 },
];

describe("compareBy", () => {
  it("keeps missing values last in both directions", () => {
    const desc = [...rows].sort(compareBy((r) => r.cpu, "desc")).map((r) => r.cpu);
    const asc = [...rows].sort(compareBy((r) => r.cpu, "asc")).map((r) => r.cpu);

    expect(desc).toEqual([12, 4, 1.5, null]);
    expect(asc).toEqual([1.5, 4, 12, null]);
  });

  it("sorts text case-insensitively and numerically", () => {
    const names = ["proc10", "Proc2", "proc1"].sort((a, b) => compareBy<string>((x) => x)(a, b));

    expect(names).toEqual(["proc1", "Proc2", "proc10"]);
  });
});

describe("listPage", () => {
  it("filters, sorts and pages, reporting the matching total", () => {
    const page = listPage(rows, {
      filter: (r) => matchesText("exe", r.name),
      compare: compareBy((r) => r.name),
      page: 2,
      pageSize: 2,
    });

    expect(page.total).toBe(3);
    expect(page.pages).toBe(2);
    expect(page.items.map((r) => r.name)).toEqual(["svchost.exe"]);
  });

  it("clamps the page when a filter shrinks the list", () => {
    const page = listPage(rows, { filter: (r) => r.name === "System", page: 9, pageSize: 2 });

    expect(page.page).toBe(1);
    expect(page.items).toHaveLength(1);
  });

  it("does not mutate its input", () => {
    const copy = [...rows];
    listPage(rows, { compare: compareBy((r) => r.cpu, "desc"), page: 1, pageSize: 10 });

    expect(rows).toEqual(copy);
  });
});

describe("matchesText and distinct", () => {
  it("matches any field, ignoring case and blanks", () => {
    expect(matchesText("  SVC ", "x", "svchost")).toBe(true);
    expect(matchesText("", null)).toBe(true);
    expect(matchesText("zzz", null, 42)).toBe(false);
    expect(matchesText("42", null, 42)).toBe(true);
  });

  it("lists distinct values for filter menus", () => {
    expect(distinct(["b", null, "a", "b", ""], (x) => x)).toEqual(["a", "b"]);
  });
});
