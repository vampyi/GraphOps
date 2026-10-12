// three connected nodes, one marked critical: a small graph as the mark
export default function Logo() {
  return (
    <svg className="logo" viewBox="0 0 24 24" aria-hidden="true">
      <line x1="5" y1="17" x2="12" y2="6" />
      <line x1="12" y1="6" x2="19" y2="16" />
      <line x1="5" y1="17" x2="19" y2="16" />
      <circle cx="5" cy="17" r="3" className="n" />
      <circle cx="12" cy="6" r="3" className="n" />
      <circle cx="19" cy="16" r="3" className="n crit" />
    </svg>
  );
}
