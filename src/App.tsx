import { useState } from "react";
import { AnimatePresence } from "motion/react";
import { Home } from "./screens/Home";
import { CreateVault } from "./screens/CreateVault";
import { AddVault } from "./screens/AddVault";
import { VaultBrowser } from "./screens/VaultBrowser";

type Screen =
  | { kind: "home" }
  | { kind: "create" }
  | { kind: "add" }
  | { kind: "browser"; path: string };

export default function App() {
  const [screen, setScreen] = useState<Screen>({ kind: "home" });

  return (
    <div className="aurora min-h-full">
      <AnimatePresence mode="wait">
        {screen.kind === "home" && (
          <Home
            key="home"
            onCreate={() => setScreen({ kind: "create" })}
            onAdd={() => setScreen({ kind: "add" })}
            onOpen={(path) => setScreen({ kind: "browser", path })}
          />
        )}
        {screen.kind === "create" && (
          <CreateVault
            key="create"
            onBack={() => setScreen({ kind: "home" })}
            onDone={(path) => setScreen({ kind: "browser", path })}
          />
        )}
        {screen.kind === "add" && (
          <AddVault
            key="add"
            onBack={() => setScreen({ kind: "home" })}
            onDone={(path) => setScreen({ kind: "browser", path })}
          />
        )}
        {screen.kind === "browser" && (
          <VaultBrowser
            key={screen.path}
            path={screen.path}
            onLock={() => setScreen({ kind: "home" })}
          />
        )}
      </AnimatePresence>
    </div>
  );
}
