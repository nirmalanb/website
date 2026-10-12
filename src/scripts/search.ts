type GuideIndexEntry = {
  id: string;
  href: string;
  title: string;
  excerpt: string;
  tags: string[];
  body: string;
};

const mountSelector = '[data-search-mount]';

function searchableText(entry: GuideIndexEntry) {
  return [entry.title, entry.excerpt, entry.tags.join(' '), entry.body].join(' ').toLowerCase();
}

function buildControls(root: HTMLElement, onQuery: (value: string) => void) {
  const input = document.createElement('input');
  input.type = 'search';
  input.className =
    'w-full rounded-lg border border-rule bg-white px-3 py-2 text-[15px] text-ink placeholder:text-mute focus-visible:border-accent focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-bright';
  input.placeholder = 'Search guides';
  input.setAttribute('aria-label', 'Search guides');
  input.setAttribute('spellcheck', 'false');
  input.addEventListener('input', () => onQuery(input.value));

  const count = document.createElement('p');
  count.className = 'mt-2 text-[13px] text-mute';
  count.setAttribute('role', 'status');
  count.setAttribute('aria-live', 'polite');

  root.append(input, count);
  return { input, count };
}

function applyFilter(items: HTMLElement[], haystacks: Map<string, string>, query: string) {
  const terms = query.toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;

  for (const item of items) {
    const haystack = haystacks.get(item.dataset.guideId ?? '') ?? '';
    const matches = terms.every((term) => haystack.includes(term));
    item.hidden = !matches;
    if (matches) shown += 1;
  }

  return shown;
}

async function initSearch() {
  const root = document.querySelector<HTMLElement>(mountSelector);
  if (!root) return;

  const response = await fetch('/search-index.json');
  if (!response.ok) return;

  const guides: GuideIndexEntry[] = await response.json();
  const haystacks = new Map(guides.map((guide) => [guide.id, searchableText(guide)]));
  const items = [...document.querySelectorAll<HTMLElement>('li[data-guide-id]')];

  const { input, count } = buildControls(root, (value) => {
    const shown = applyFilter(items, haystacks, value);
    count.textContent = value.trim() ? `${shown} of ${items.length} match “${value.trim()}”` : '';
  });

  input.addEventListener('keydown', (event) => {
    if (event.key !== 'Escape' || !input.value) return;
    input.value = '';
    applyFilter(items, haystacks, '');
    count.textContent = '';
  });
}

void initSearch();
