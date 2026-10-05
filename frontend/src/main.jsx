import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
// Fonts are bundled, so the dashboard looks the same inside a laboratory with no internet.
import "@fontsource-variable/dm-sans";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource/poppins/300.css";
import "@fontsource/poppins/500.css";
import "@fontsource/poppins/600.css";
import "@fontsource/playfair-display/900.css";
import App from "./App.jsx";
import "./styles.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
