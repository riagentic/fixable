// Inline SVG art. Logo mirrors src/icon.svg (the app icon) so the window and
// the dock show the same mark; AllClear marks an empty view.

export function Logo() {
  return (
    <svg className="logo" viewBox="0 0 512 512" aria-hidden="true">
      <defs>
        <linearGradient id="fx-tile" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#3b8bff" />
          <stop offset="1" stopColor="#1650c4" />
        </linearGradient>
        <mask id="fx-jaw">
          <rect width="512" height="512" fill="#fff" />
          <g transform="rotate(-50.7 372 176)">
            <rect x="372" y="150" width="90" height="52" fill="#000" />
            <circle cx="372" cy="176" r="26" fill="#000" />
          </g>
        </mask>
      </defs>
      <rect
        x="16"
        y="16"
        width="480"
        height="480"
        rx="108"
        fill="url(#fx-tile)"
      />
      <g transform="translate(-16 14)">
        <g
          fill="#fff"
          stroke="#fff"
          strokeLinecap="round"
          strokeLinejoin="round"
          mask="url(#fx-jaw)"
        >
          <path d="M132 272 L222 360 L352 200" fill="none" strokeWidth="64" />
          <circle cx="372" cy="176" r="76" stroke="none" />
        </g>
      </g>
    </svg>
  );
}

// A shield with a check: nothing to fix here.
export function AllClear() {
  return (
    <svg className="all-clear" viewBox="0 0 64 64" aria-hidden="true">
      <path
        d="M32 5 L54 13 V30 C54 45 44 55 32 59 C20 55 10 45 10 30 V13 Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <path
        d="M22 32 L29 39 L43 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="4"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
