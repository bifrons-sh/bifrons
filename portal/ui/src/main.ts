// Entry point — kept tiny so code-splitting isn't necessary. The router
// and views live in app.ts; this file exists solely as a Vite-friendly
// HTML anchor point and to centralise unhandled-rejection telemetry.

import { bootstrap } from './app.js';

window.addEventListener('error', (e) => {
  // Surface to the console with a tag — avoids silent JS failures going
  // unnoticed in a kiosk-style operator display.
  console.error('[portal-ui] error', e.error ?? e.message);
});
window.addEventListener('unhandledrejection', (e) => {
  console.error('[portal-ui] unhandled rejection', e.reason);
});

void bootstrap();
