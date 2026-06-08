// dvoid self-host: notify the embedding shell of the active app context.
//
// The dvoid shell embeds this AFFiNE web app in a CROSS-ORIGIN iframe
// (affine.dvoid.io inside app.dvoid.io). The parent shell cannot read the
// iframe's URL or React state, so we push the active app context (workspace +
// open doc) up via postMessage whenever it first becomes known and on every
// change. The shell uses this to sync context to its chat agent.
//
// The envelope is intentionally generalized (`dvoid-app-context` / `app`) so
// other embedded apps can adopt the same parent<->child protocol later; only
// the `context` payload is app-specific.
//
// Kept as an isolated leaf module (org-specific, never upstream) so the only
// touch to a shared file is a single hook call — rebases clean.
import { useEffect } from 'react';
import { combineLatest, of, switchMap } from 'rxjs';

import type { GlobalContextService } from '../global-context';
import type { Workspace } from './entities/workspace';

const DVOID_SHELL_ORIGIN = 'https://app.dvoid.io';

interface DvoidAppContext {
  workspaceId: string;
  workspaceName: string | undefined;
  docId: string | undefined;
  docTitle: string | undefined;
}

/**
 * Subscribe to the active workspace (id + name) and the open doc (id + title)
 * and post a `dvoid-app-context` message to the parent shell. No-op when not
 * running inside an iframe.
 *
 * Reactive sources (all canonical AFFiNE LiveData — no URL parsing, no polling):
 * - workspaceId   → `workspace.id`
 * - workspaceName → `workspace.name$` (LiveData over root-doc yjs `meta.name`)
 * - docId         → `GlobalContext.docId.$` — set by the doc detail page only
 *   while a doc is the active editor view (detail-page.tsx, guarded by
 *   `isActiveView`), and cleared to `null` on unmount. Every non-doc view
 *   (all / trash / collection / tag / setting / journals / home) therefore
 *   leaves it `null`, so "no open doc" needs no segment allow-list.
 * - docTitle      → `workspace.docs.list.doc$(docId)?.title$` (DocRecord.title$)
 *
 * De-duplicates: skips emitting when the full context snapshot is byte-identical
 * to the previously emitted one (a no-op LiveData tick never reaches the parent).
 */
export function useNotifyDvoidParent(
  workspace: Workspace | null,
  globalContextService: GlobalContextService
) {
  useEffect(() => {
    // Only relevant when embedded in the dvoid shell iframe.
    if (typeof window === 'undefined' || window.parent === window) {
      return;
    }
    if (!workspace) {
      return;
    }

    const workspaceId = workspace.id;
    const docId$ = globalContextService.globalContext.docId.$;
    const docs = workspace.docs;

    // Resolve the open doc's title reactively from its record. When no doc is
    // open (docId null) or the record isn't known yet, title is undefined.
    const docTitle$ = docId$.pipe(
      switchMap(docId =>
        docId
          ? docs.list
              .doc$(docId)
              .pipe(switchMap(record => record?.title$ ?? of(undefined)))
          : of(undefined)
      )
    );

    let lastSnapshot: string | undefined;

    const subscription = combineLatest([
      workspace.name$,
      docId$,
      docTitle$,
    ]).subscribe(([workspaceName, docId, docTitle]) => {
      const context: DvoidAppContext = {
        workspaceId,
        workspaceName,
        docId: docId ?? undefined,
        // title$ defaults to '' in AFFiNE; normalize empty → undefined.
        docTitle: docTitle || undefined,
      };

      const snapshot = JSON.stringify(context);
      if (snapshot === lastSnapshot) {
        return;
      }
      lastSnapshot = snapshot;

      window.parent.postMessage(
        { source: 'dvoid-app-context', app: 'affine', context },
        DVOID_SHELL_ORIGIN
      );
    });

    return () => {
      subscription.unsubscribe();
    };
  }, [workspace, globalContextService]);
}
