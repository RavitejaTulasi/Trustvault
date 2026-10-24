import { listDocuments } from '../auth';
import type { DocumentListItem } from '../types';

const MAX_PAGES = 20;

/**
 * Walk the server-side pagination for documents the caller may access.
 * The API caps page_size at 100, so this is used only for views that need the
 * complete visible set (Shared With Me / Access & Sharing) and is explicitly
 * bounded so a large tenant cannot produce an unbounded request loop.
 */
export async function fetchAllVisibleDocuments(options: {
  ownerId?: string;
} = {}): Promise<DocumentListItem[]> {
  const items: DocumentListItem[] = [];
  let page = 1;
  let total = Infinity;

  while (page <= MAX_PAGES && items.length < total) {
    const result = await listDocuments({
      page,
      page_size: 100,
      owner_id: options.ownerId,
    });
    items.push(...result.documents);
    total = result.total;
    if (result.documents.length === 0) {
      break;
    }
    page += 1;
  }

  return items;
}
