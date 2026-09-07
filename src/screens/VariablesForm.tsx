import { useEffect, useRef, useState } from "react";

interface Props {
  title: string;
  variables: string[];
  onCancel: () => void;
  onSubmit: (vars: Record<string, string>) => void;
}

export function VariablesForm({ title, variables, onCancel, onSubmit }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() =>
    Object.fromEntries(variables.map((v) => [v, ""])),
  );
  const first = useRef<HTMLInputElement>(null);

  useEffect(() => {
    first.current?.focus();
  }, []);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    onSubmit(values);
  };

  return (
    <form className="editor" onSubmit={submit}>
      <div className="editor-head">
        <strong>Fill in: {title}</strong>
      </div>
      {variables.map((v, i) => (
        <label key={v} className="var-row">
          <span>{v}</span>
          <input
            ref={i === 0 ? first : undefined}
            value={values[v]}
            onChange={(e) => setValues({ ...values, [v]: e.target.value })}
            placeholder={v}
          />
        </label>
      ))}
      <div className="editor-actions">
        <button type="button" className="ghost" onClick={onCancel}>Cancel (Esc)</button>
        <button type="submit">Paste (Enter)</button>
      </div>
    </form>
  );
}
