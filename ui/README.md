# sandbox — Protected AI Layer

A React + Vite landing and demo UI for the **Security Proxy Layer**: the layer that sits between AI agents and the world to protect against prompt injection, goal hijacking, context poisoning, tool misuse, and data exfiltration (with canary-based leak detection).

## Design

- **Colors**: Giskard-style palette — dark teal background (`#0d2827`, `#103332`), lime green (`#76F516`), and cyan (`#22E8DC`) for accents.
- **Layout**: Hero headline, centered **AI agent prompt** generator with a single **Change scenarios** button to cycle demo scenarios, then problem/solution/how-it-works sections, and an **All your questions answered** FAQ at the bottom. All other buttons have been removed.

## Tech

- **React 18** + **Vite 6**
- No backend; static demo scenarios cycle on "Change scenarios".

## Commands

```bash
npm install
npm run dev    # dev server at http://localhost:5173
npm run build  # production build
npm run preview # preview production build
```

## Structure

- `src/App.jsx` — main layout and demo scenario state
- `src/components/` — Header, Hero, PromptGenerator, Problem, Solution, HowItWorks, FAQ, Footer
- `src/index.css` — global Giskard-style variables
- Each component has its own `.css` in the same folder
