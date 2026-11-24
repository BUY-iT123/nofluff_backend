const assert = require("node:assert/strict");
const test = require("node:test");
const { hasSameNonWhitespaceCharacters, validatePostReadyText } = require("../post-ready-utils");

test("allows only paragraph whitespace changes while keeping emojis and style exact", () => {
  const original = "I LOVE this 😭😭. Pleaseeeee keep it!!";
  const formatted = "I LOVE this 😭😭.\n\nPleaseeeee keep it!!";
  assert.equal(hasSameNonWhitespaceCharacters(original, formatted), true);
});

test("rejects changed capitals, punctuation, emoji, or word order", () => {
  const original = "I LOVE this 😭. Pleaseeeee keep it!!";
  for (const formatted of [
    "I love this 😭. Pleaseeeee keep it!!",
    "I LOVE this 😭! Pleaseeeee keep it!!",
    "I LOVE this. Pleaseeeee keep it!!",
    "Pleaseeeee keep it!! I LOVE this 😭.",
  ]) {
    assert.equal(hasSameNonWhitespaceCharacters(original, formatted), false);
  }
});

test("keeps an unfinished ending unchanged when only a blank line is added", () => {
  const original = "The first thought is done. The last one is unfinished because";
  const formatted = "The first thought is done.\n\nThe last one is unfinished because";
  assert.equal(hasSameNonWhitespaceCharacters(original, formatted), true);
  assert.deepEqual(validatePostReadyText(original, formatted), { result: formatted, formatted: true });
});

test("returns the original text and exact retry message if any non-whitespace character changes", () => {
  const original = "I LOVE this 😭. Pleaseeeee keep it!!";
  const answer = validatePostReadyText(original, "I love this 😭. Please keep it!!");
  assert.deepEqual(answer, {
    result: original,
    formatted: false,
    error: "Couldn't format this one. Try again.",
  });
});
