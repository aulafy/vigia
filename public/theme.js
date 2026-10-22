// Applied before first paint, so the page never flashes the wrong theme
try { var t = localStorage.getItem('vigia-theme'); if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t; } catch (e) {}
