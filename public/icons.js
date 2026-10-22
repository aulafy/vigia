// Icon set from REM-L (MIT, same author): 24-unit grid, 1.75 stroke, plus a translucent fill layer that gives the line body.
// Vigía-specific glyphs (firewall, globe, bell, more, ext, chevron) follow the same grammar.
const P = {
  hoy: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9v11a1 1 0 0 0 1 1h3.5v-6h5v6H18a1 1 0 0 0 1-1V9"/>',
  alert: '<path d="M10.3 4 2.5 17.6A2 2 0 0 0 4.2 20.6h15.6a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4"/><path d="M12 17h.01"/>',
  clientes: '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20.5a6.5 6.5 0 0 1 13 0"/><path d="M15.5 4.7a3.5 3.5 0 0 1 0 6.6"/><path d="M18 14.2a6.5 6.5 0 0 1 3.5 6.3"/>',
  equipos: '<rect x="3" y="5" width="18" height="14" rx="2.5"/><path d="M3 9.7h18M3 14.3h18M9 5v4.7M15 5v4.7M12 9.7v4.6M7.5 14.3V19M16.5 14.3V19"/>',
  copias: '<rect x="3" y="4" width="18" height="4.5" rx="1.2"/><path d="M5 8.5V19a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8.5"/><path d="M10 12.5h4"/>',
  informes: '<path d="M4 4v16h16"/><path d="M8.5 16v-4M12.5 16V8M16.5 16v-6.5"/>',
  ajustes: '<path d="M4 7h8M17 7h3M4 17h3M12 17h8"/><circle cx="14.5" cy="7" r="2.5"/><circle cx="9.5" cy="17" r="2.5"/>',
  more: '<circle cx="6" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="18" cy="12" r="1.3"/>',
  shield: '<path d="M12 3 4.5 6v5.5c0 4.4 3 7.7 7.5 9 4.5-1.3 7.5-4.6 7.5-9V6z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
  globe: '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.5 2.6 3.5 5.4 3.5 8.5s-1 5.9-3.5 8.5c-2.5-2.6-3.5-5.4-3.5-8.5s1-5.9 3.5-8.5z"/>',
  bell: '<path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
  lock: '<rect x="5" y="10.5" width="14" height="9.5" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
  check: '<path d="m4.5 12.5 5 5L19.5 7"/>', x: '<path d="M6 6l12 12M18 6 6 18"/>', plus: '<path d="M12 5v14M5 12h14"/>',
  search: '<circle cx="11" cy="11" r="6.5"/><path d="m20.5 20.5-4.2-4.2"/>',
  refresh: '<path d="M20 12a8 8 0 0 0-14-5.3L4 9"/><path d="M4 4.5V9h4.5"/><path d="M4 12a8 8 0 0 0 14 5.3L20 15"/><path d="M20 19.5V15h-4.5"/>',
  ext: '<path d="M14 4h6v6"/><path d="M20 4l-9 9"/><path d="M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10"/>',
  chevron: '<path d="m9 6 6 6-6 6"/>', back: '<path d="M19.5 12h-15"/><path d="m10.5 6-6 6 6 6"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"/>',
  moon: '<path d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5a8.5 8.5 0 1 0 10.7 10.7z"/>',
  phone: '<path d="M5.5 3.5h3l1.8 4.6-2.2 1.4a11 11 0 0 0 5.4 5.4l1.4-2.2 4.6 1.8v3a1.5 1.5 0 0 1-1.6 1.5A15.5 15.5 0 0 1 4 5.1 1.5 1.5 0 0 1 5.5 3.5z"/>',
  print: '<path d="M7 9V3.5h10V9"/><path d="M7 17.5H5.5a1.5 1.5 0 0 1-1.5-1.5v-5a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v5a1.5 1.5 0 0 1-1.5 1.5H17"/><rect x="7" y="14" width="10" height="6.5" rx="1"/>',
};
const F = {
  hoy: '<path d="M5 9.2 12 3.4l7 5.8V20a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1z"/>', alert: '<path d="M10.3 4 2.5 17.6A2 2 0 0 0 4.2 20.6h15.6a2 2 0 0 0 1.7-3L13.7 4a2 2 0 0 0-3.4 0z"/>',
  clientes: '<circle cx="9" cy="8" r="3.5"/>', equipos: '<rect x="3" y="5" width="18" height="14" rx="2.5"/>', copias: '<rect x="3" y="4" width="18" height="4.5" rx="1.2"/>',
  informes: '<rect x="7.5" y="12" width="2" height="4.5" rx="1"/><rect x="11.5" y="8" width="2" height="8.5" rx="1"/><rect x="15.5" y="9.5" width="2" height="7" rx="1"/>',
  ajustes: '<circle cx="14.5" cy="7" r="2.5"/><circle cx="9.5" cy="17" r="2.5"/>', shield: '<path d="M12 3 4.5 6v5.5c0 4.4 3 7.7 7.5 9 4.5-1.3 7.5-4.6 7.5-9V6z"/>',
  more: '<circle cx="6" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="18" cy="12" r="1.3"/>', globe: '<circle cx="12" cy="12" r="8.5"/>',
  bell: '<path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z"/>', clock: '<circle cx="12" cy="12" r="8.5"/>', lock: '<rect x="5" y="10.5" width="14" height="9.5" rx="2.5"/>',
  sun: '<circle cx="12" cy="12" r="4"/>', moon: '<path d="M20.5 14.2A8.5 8.5 0 0 1 9.8 3.5a8.5 8.5 0 1 0 10.7 10.7z"/>',
};
export const icon = (n, cls = '') => `<svg class="ic ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${F[n] ? `<g class="ic-f" fill="currentColor" stroke="none">${F[n]}</g>` : ''}${P[n] || ''}</svg>`;
export const ICONS = Object.keys(P);
