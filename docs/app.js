const copyButton = document.querySelector('[data-copy-target]');

if (copyButton) {
  copyButton.addEventListener('click', async () => {
    const target = document.getElementById(copyButton.dataset.copyTarget);
    if (!target) return;

    try {
      await navigator.clipboard.writeText(target.textContent.trim());
      const original = copyButton.textContent;
      copyButton.textContent = 'Copied';
      setTimeout(() => { copyButton.textContent = original; }, 1600);
    } catch {
      copyButton.textContent = 'Select manually';
    }
  });
}
