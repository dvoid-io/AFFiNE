import { Logo1Icon } from '@blocksuite/icons/rc';
import { useTheme } from 'next-themes';
import { type ReactNode } from 'react';

import dotBgDark from './assets/dot-bg.dark.png';
import dotBgLight from './assets/dot-bg.light.png';
import { DesktopNavbar } from './desktop-navbar';
import * as styles from './index.css';
import { MobileNavbar } from './mobile-navbar';

export const AffineOtherPageLayout = ({
  children,
}: {
  children: ReactNode;
}) => {
  const { resolvedTheme } = useTheme();
  const backgroundImage =
    resolvedTheme === 'dark' && dotBgDark ? dotBgDark : dotBgLight;

  return (
    <div
      className={styles.root}
      style={{ backgroundImage: `url(${backgroundImage})` }}
    >
      {BUILD_CONFIG.isElectron ? (
        <div className={styles.draggableHeader} />
      ) : (
        <div className={styles.topNav}>
          <a href="/" rel="noreferrer" className={styles.affineLogo}>
            <Logo1Icon width={24} height={24} />
          </a>

          <DesktopNavbar />
          {/* dvoid self-host: "Download app" CTA removed (org-specific, never upstream). */}
          <MobileNavbar />
        </div>
      )}

      {children}
    </div>
  );
};
