const btn = document.getElementById('preview-print-btn');
if (btn) {
  btn.addEventListener('click', () => window.print());
}

if (document.body?.dataset?.autoPrint === 'true') {
  window.addEventListener('load', () => {
    setTimeout(() => window.print(), 250);
  });
}
