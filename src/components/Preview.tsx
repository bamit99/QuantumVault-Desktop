import { useEffect, useMemo, useState } from "react";
import { motion } from "motion/react";
import { X } from "@phosphor-icons/react";
import { formatSize, type ExtractedFile } from "../lib/api";

function isTextLike(name: string, mime: string) {
  if (mime.startsWith("text/")) return true;
  return /\.(txt|md|json|csv|log|xml|yml|yaml|html|css|js|ts|tsx|jsx|ini|toml|rs|py|go|java|c|cpp|h|sh|bat|ps1)$/i.test(
    name,
  );
}

export function PreviewModal({
  file,
  onClose,
}: {
  file: ExtractedFile;
  onClose: () => void;
}) {
  const isImage = file.mime.startsWith("image/");
  const isText = isTextLike(file.name, file.mime);

  const url = useMemo(() => {
    if (!isImage) return "";
    const blob = new Blob([new Uint8Array(file.data)], { type: file.mime });
    return URL.createObjectURL(blob);
  }, [file, isImage]);

  const [text, setText] = useState("");

  useEffect(() => {
    if (isText) {
      try {
        setText(new TextDecoder().decode(new Uint8Array(file.data)));
      } catch {
        setText("");
      }
    }
    return () => {
      if (url) URL.revokeObjectURL(url);
    };
  }, [file, isText, url]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const baseName = file.name.split("/").pop() ?? file.name;

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6 backdrop-blur-sm"
      onClick={onClose}
    >
      <motion.div
        initial={{ opacity: 0, scale: 0.96 }}
        animate={{ opacity: 1, scale: 1 }}
        exit={{ opacity: 0, scale: 0.96 }}
        transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
        onClick={(e) => e.stopPropagation()}
        className="glass-strong flex max-h-[85vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl"
      >
        <div className="flex items-center justify-between border-b border-line px-5 py-3">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-ink">{baseName}</p>
            <p className="mono-value text-[11px]">
              {formatSize(file.data.length)} · {file.mime}
            </p>
          </div>
          <button
            onClick={onClose}
            className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-dim hover:text-ink hover:bg-surface-2 transition-colors cursor-pointer"
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="min-h-0 flex-1 overflow-auto p-5">
          {isImage && url ? (
            <img
              src={url}
              alt={baseName}
              className="mx-auto max-h-full rounded-lg object-contain"
            />
          ) : isText ? (
            <pre className="whitespace-pre-wrap break-words font-mono text-[13px] leading-relaxed text-ink-dim">
              {text || "(empty file)"}
            </pre>
          ) : (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <p className="text-sm text-ink-dim">Preview isn't available for this file type.</p>
              <p className="mt-1 text-xs text-ink-faint">
                Use “Extract” to save it and open it in your default application.
              </p>
            </div>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
