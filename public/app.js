const form = document.querySelector("[data-proxy-form]");
const input = document.querySelector("[data-proxy-input]");
const status = document.querySelector("[data-form-status]");

form?.addEventListener("submit", (event) => {
  const value = input.value.trim();
  if (!value) {
    event.preventDefault();
    status.textContent = "Enter an address first.";
    input.focus();
  }
});

document.querySelectorAll("[data-target]").forEach((button) => {
  button.addEventListener("click", () => {
    input.value = button.dataset.target;
    form.requestSubmit();
  });
});
