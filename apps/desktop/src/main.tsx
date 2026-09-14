import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import RequestPopup from "./RequestPopup";
import "./styles.css";

const root = document.getElementById("root");
if (root)
  createRoot(root).render(
    <StrictMode>
      {new URLSearchParams(window.location.search).has("request") ? (
        <RequestPopup />
      ) : (
        <App />
      )}
    </StrictMode>,
  );
