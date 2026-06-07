// dvoid self-host: the "open in / download the desktop app" banner is removed
// (org-specific, will never go upstream). Neutered at the leaf component so the
// banner-trigger logic and render sites stay untouched and rebase clean.
export const OpenInAppCard = () => {
  return null;
};
