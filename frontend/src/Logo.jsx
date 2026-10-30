// the mark: a shield drawn around a small graph — the teal hub watching, one neighbor marked critical
export default function Logo() {
  return (
    <svg className="logo" viewBox="0 0 24 24" aria-hidden="true">
      <path className="sh" d="M12 2.8 L19.2 5.6 V10.8 C19.2 15.8 16.4 19.3 12 21.2 C7.6 19.3 4.8 15.8 4.8 10.8 V5.6 Z" />
      <line x1="12" y1="8.8" x2="8.7" y2="14.1" />
      <line x1="12" y1="8.8" x2="15.3" y2="14.1" />
      <circle cx="12" cy="8.8" r="2.1" className="n" />
      <circle cx="8.7" cy="14.1" r="1.7" className="d" />
      <circle cx="15.3" cy="14.1" r="1.7" className="crit" />
    </svg>
  );
}
