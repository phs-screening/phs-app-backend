const {
  buildNamePrefixFilter,
  buildNameSearchPrefixes,
  normalizeNameSearch,
  validateNameSearch,
} = require("../../server/utils/nameSearch");

function matchesFilter(filter, field, value) {
  const available = buildNameSearchPrefixes(value);
  return filter[field].$all.every((prefix) => available.includes(prefix));
}

describe("nameSearch", () => {
  it("normalizes whitespace and creates unique lowercase token prefixes", () => {
    expect(normalizeNameSearch("  Mel   Tan  ")).toBe("Mel Tan");
    expect(buildNameSearchPrefixes("Mel Mel")).toEqual(["m", "me", "mel"]);
  });

  it("matches a surname token regardless of its position", () => {
    const filter = buildNamePrefixFilter("prefixes", "Lou");

    expect(matchesFilter(filter, "prefixes", "Lou J")).toBe(true);
    expect(matchesFilter(filter, "prefixes", "J Lou")).toBe(true);
    expect(matchesFilter(filter, "prefixes", "Malou J")).toBe(false);
  });

  it("matches multiple token prefixes in any order", () => {
    const filter = buildNamePrefixFilter("prefixes", "Yeo Z");

    expect(filter).toEqual({ prefixes: { $all: ["yeo", "z"] } });
    expect(matchesFilter(filter, "prefixes", "Yeo Z W D")).toBe(true);
    expect(matchesFilter(filter, "prefixes", "Z W D Yeo")).toBe(true);
    expect(matchesFilter(filter, "prefixes", "Yeo A B")).toBe(false);
  });

  it("preserves punctuation and creates prefixes at punctuation boundaries", () => {
    expect(buildNameSearchPrefixes("S/O Ramasamy")).toEqual(
      expect.arrayContaining(["s", "s/", "s/o", "o", "r", "ra"]),
    );
    expect(matchesFilter(buildNamePrefixFilter("prefixes", "Tan."), "prefixes", "Tan. J"))
      .toBe(true);
    expect(matchesFilter(buildNamePrefixFilter("prefixes", "Tan."), "prefixes", "Tanya J"))
      .toBe(false);
  });

  it.each([
    ["Tan", "Mel Tan", true],
    ["Chen", "Chen R Y", true],
    ["Christie", "Christie T E N", true],
    ["Mel Tan", "Mel Tan", true],
    ["Tan M", "Mel Tan", true],
    ["TAN", "Mel Tan", true],
    ["tan", "Mel Tan", true],
    ["Zzxq", "Mel Tan", false],
  ])("matches fixture query %s against %s", (query, name, expected) => {
    expect(matchesFilter(buildNamePrefixFilter("prefixes", query), "prefixes", name))
      .toBe(expected);
  });

  it("enforces one two-character token without a Unicode exception", () => {
    expect(validateNameSearch(" ").valid).toBe(false);
    expect(validateNameSearch("A B").valid).toBe(false);
    expect(validateNameSearch("A Lou").valid).toBe(true);
    expect(validateNameSearch("\u674e").valid).toBe(false);
    expect(validateNameSearch("\u674e\u738b").valid).toBe(true);
    expect(validateNameSearch("A".repeat(101)).valid).toBe(false);
    expect(
      validateNameSearch("one two three four five six seven eight nine").valid,
    ).toBe(false);
  });
});
