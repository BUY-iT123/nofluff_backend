function hasSameNonWhitespaceCharacters(original, formatted) {
  return original.replace(/\s/gu, "") === formatted.replace(/\s/gu, "");
}

function validatePostReadyText(original, formatted) {
  if (hasSameNonWhitespaceCharacters(original, formatted)) {
    return { result: formatted, formatted: true };
  }
  return {
    result: original,
    formatted: false,
    error: "Couldn't format this one. Try again.",
  };
}

module.exports = { hasSameNonWhitespaceCharacters, validatePostReadyText };
