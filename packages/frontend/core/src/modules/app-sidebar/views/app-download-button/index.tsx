// dvoid self-host: the "Download App" sidebar CTA is removed (org-specific,
// will never go upstream). Neutered at the leaf component so the churny
// render site (root-app-sidebar) stays untouched and rebases clean.
export function AppDownloadButton(_props: {
  className?: string;
  style?: React.CSSProperties;
}) {
  return null;
}
