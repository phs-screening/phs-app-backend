const {
  buildNameTokenPrefixFilter,
  validateNameSearch,
} = require("../../server/utils/nameSearch");

function matchesFilter(filter, field, value) {
  const conditions = filter.$and || [filter];
  return conditions.every((condition) => {
    const expression = condition[field];
    return new RegExp(expression.$regex, expression.$options).test(value);
  });
}

describe("nameSearch", () => {
  it("matches a surname token regardless of its position", () => {
    const filter = buildNameTokenPrefixFilter("initials", "Lou");

    expect(matchesFilter(filter, "initials", "Lou J")).toBe(true);
    expect(matchesFilter(filter, "initials", "J Lou")).toBe(true);
    expect(matchesFilter(filter, "initials", "Malou J")).toBe(false);
  });

  it("matches multiple token prefixes in any order", () => {
    const filter = buildNameTokenPrefixFilter("initials", "Yeo Z");

    expect(matchesFilter(filter, "initials", "Yeo Z W D")).toBe(true);
    expect(matchesFilter(filter, "initials", "Z W D Yeo")).toBe(true);
    expect(matchesFilter(filter, "initials", "Yeo A B")).toBe(false);
  });

  it("escapes regex characters supplied by the user", () => {
    const filter = buildNameTokenPrefixFilter("initials", "Tan.");

    expect(matchesFilter(filter, "initials", "Tan. J")).toBe(true);
    expect(matchesFilter(filter, "initials", "Tanya J")).toBe(false);
  });

  it("rejects blank, single-character-only, long, and excessive-token searches", () => {
    expect(validateNameSearch(" ").valid).toBe(false);
    expect(validateNameSearch("A B").valid).toBe(false);
    expect(validateNameSearch("A Lou").valid).toBe(true);
    expect(validateNameSearch("\u674e").valid).toBe(true);
    expect(validateNameSearch("A".repeat(101)).valid).toBe(false);
    expect(
      validateNameSearch("one two three four five six seven eight nine").valid,
    ).toBe(false);
  });
});
