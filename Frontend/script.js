const API_URL = "http://127.0.0.1:5001/detect_url";

const form = document.getElementById("scan-form");
const urlInput = document.getElementById("url-input");
const scanButton = document.getElementById("scan-button");
const buttonText = document.getElementById("button-text");
const clearButton = document.getElementById("clear-button");
const errorMessage = document.getElementById("error-message");
const resultPanel = document.getElementById("result-panel");

document.querySelectorAll(".example-chip").forEach((button) => {
  button.addEventListener("click", () => {
    urlInput.value = button.dataset.url;
    urlInput.focus();
  });
});

clearButton.addEventListener("click", () => {
  urlInput.value = "";
  urlInput.focus();
  errorMessage.hidden = true;
});

function riskClass(level) {
  const normalized = String(level || "").toLowerCase();
  if (normalized === "low") return "low";
  if (normalized === "medium") return "medium";
  return "high";
}

function displayResult(result, enteredUrl) {
  const score = Math.max(0, Math.min(100, Number(result.risk_score) || 0));
  const level = result.risk_level || "Unknown";
  const levelClass = riskClass(level);

  let prediction = "Potentially Malicious";
  if (levelClass === "low") prediction = "Likely Legitimate";
  if (levelClass === "medium") prediction = "Suspicious URL";

  document.getElementById("result-title").textContent = "Analysis complete";
  const pill = document.getElementById("risk-pill");
  pill.className = `risk-pill ${levelClass}`;
  pill.textContent = `${String(level).toUpperCase()} RISK`;

  document.getElementById("score-number").textContent = score;
  document.getElementById("ring-number").textContent = `${score}%`;
  document.getElementById("prediction").textContent = prediction;
  document.getElementById("prediction").style.color =
    levelClass === "low" ? "var(--green)" :
    levelClass === "medium" ? "var(--yellow)" : "var(--red)";
  document.getElementById("explanation").textContent =
    result.explanation || "Analysis completed.";

  const fill = document.getElementById("meter-fill");
  fill.className = `meter-fill ${levelClass}`;
  fill.style.width = `${score}%`;

  const ring = document.getElementById("score-ring");
  ring.className = `score-ring ${levelClass}`;

  const meterTrack = document.getElementById("meter-track");
  meterTrack.setAttribute("aria-valuenow", String(score));

  const list = document.getElementById("indicators-list");
  list.replaceChildren();
  const indicators = Array.isArray(result.indicators) ? result.indicators : [];

  if (indicators.length === 0) {
    const item = document.createElement("li");
    item.className = "no-indicators";
    item.textContent = "No indicators were returned.";
    list.appendChild(item);
  } else {
    indicators.forEach((indicator) => {
      const item = document.createElement("li");
      const dot = document.createElement("span");
      dot.className = `indicator-dot ${String(indicator.severity || "info").toLowerCase()}`;
      const text = document.createElement("span");
      const name = document.createElement("span");
      name.className = "indicator-name";
      name.textContent = `${indicator.indicator || "Indicator"}: `;
      text.appendChild(name);
      text.appendChild(document.createTextNode(indicator.details || ""));
      item.appendChild(dot);
      item.appendChild(text);
      list.appendChild(item);
    });
  }

  document.getElementById("disclaimer").textContent =
    result.disclaimer ||
    "This is an automated screening result, not a guarantee of safety.";

  resultPanel.hidden = false;
  errorMessage.hidden = true;
  resultPanel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    errorMessage.textContent = "Please enter a URL to analyze.";
    errorMessage.hidden = false;
    return;
  }

  scanButton.disabled = true;
  buttonText.textContent = "Analyzing URL...";
  errorMessage.hidden = true;

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    let result;
    try {
      result = await response.json();
    } catch {
      throw new Error("The backend returned an unreadable response.");
    }

    if (!response.ok) {
      throw new Error(result.error || `Request failed (${response.status}).`);
    }

    displayResult(result, url);
  } catch (error) {
    const isNetworkError = error instanceof TypeError;
    errorMessage.textContent = isNetworkError
      ? "Could not connect to the backend. Start Backend/app.py first, then refresh this page."
      : error.message;
    errorMessage.hidden = false;
    resultPanel.hidden = true;
  } finally {
    scanButton.disabled = false;
    buttonText.textContent = "Analyze URL";
  }
});
