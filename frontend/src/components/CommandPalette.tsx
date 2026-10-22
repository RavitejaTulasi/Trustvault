import { useId, useMemo, useRef, useState } from 'react';
import type { KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import Dialog from './Dialog';
import IconButton from './IconButton';
import { CloseIcon, SearchIcon, SettingsIcon, UploadIcon } from './Icons';
import {
  canManageDocuments,
  navigationItemsForRole,
} from '../lib/navigation';
import type { NavIcon } from '../lib/navigation';

interface CommandPaletteProps {
  role: string;
  onClose: () => void;
}

interface CommandAction {
  id: string;
  label: string;
  description: string;
  icon: NavIcon;
  to: string;
  group: 'Pages' | 'Actions';
  keywords?: string[];
}

export default function CommandPalette({ role, onClose }: CommandPaletteProps) {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const listboxId = useId();

  const actions = useMemo<CommandAction[]>(() => {
    const pages: CommandAction[] = navigationItemsForRole(role).map((item) => ({
      id: item.to,
      label: item.label,
      description: item.description,
      icon: item.icon,
      to: item.to,
      group: 'Pages',
      keywords: item.keywords,
    }));
    pages.push({
      id: '/settings',
      label: 'Account settings',
      description: 'Profile, account identity, and security',
      icon: SettingsIcon,
      to: '/settings',
      group: 'Pages',
      keywords: ['profile', 'password', 'account', 'security', 'settings'],
    });
    const uploads: CommandAction[] = canManageDocuments(role)
      ? [
          {
            id: 'action-upload',
            label: 'Upload a document',
            description: 'Open the document library and choose a file',
            icon: UploadIcon,
            to: '/documents?upload=1',
            group: 'Actions',
            keywords: ['create', 'file', 'add', 'library'],
          },
        ]
      : [];
    return [...pages, ...uploads];
  }, [role]);

  const results = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (normalized === '') {
      return actions;
    }
    return actions.filter((action) =>
      [action.label, action.description, ...(action.keywords ?? [])]
        .join(' ')
        .toLowerCase()
        .includes(normalized),
    );
  }, [actions, query]);

  const groups = useMemo(
    () =>
      (['Pages', 'Actions'] as const)
        .map((group) => ({
          group,
          items: results.filter((action) => action.group === group),
        }))
        .filter((entry) => entry.items.length > 0),
    [results],
  );

  const activeAction = results[activeIndex];

  const choose = (action: CommandAction) => {
    onClose();
    navigate(action.to);
  };

  const onInputKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setActiveIndex((index) => (results.length === 0 ? 0 : (index + 1) % results.length));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setActiveIndex((index) =>
        results.length === 0 ? 0 : (index - 1 + results.length) % results.length,
      );
    } else if (event.key === 'Enter' && activeAction) {
      event.preventDefault();
      choose(activeAction);
    }
  };

  let optionIndex = -1;

  return (
    <Dialog
      label="Command palette"
      onClose={onClose}
      className="command-dialog"
      hideHeader
      initialFocusRef={inputRef}
    >
      <div className="command-search">
        <SearchIcon aria-hidden="true" />
        <input
          ref={inputRef}
          className="command-input"
          type="search"
          role="combobox"
          aria-label="Search pages and actions"
          aria-autocomplete="list"
          aria-expanded="true"
          aria-controls={listboxId}
          aria-activedescendant={
            activeAction ? `${listboxId}-option-${activeAction.id}` : undefined
          }
          placeholder="Search pages and actions…"
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setActiveIndex(0);
          }}
          onKeyDown={onInputKeyDown}
        />
        <span className="command-kbd" aria-hidden="true">
          Esc
        </span>
        <IconButton label="Close command palette" onClick={onClose}>
          <CloseIcon />
        </IconButton>
      </div>

      <div id={listboxId} className="command-results" role="listbox" aria-label="Results">
        {results.length === 0 ? (
          <div className="command-empty">
            <p className="command-empty-title">No matching pages or actions</p>
            <p className="command-empty-copy">Try a different search term.</p>
          </div>
        ) : (
          groups.map((group) => (
            <div key={group.group} role="group" aria-label={group.group}>
              <p className="command-group-label" aria-hidden="true">
                {group.group}
              </p>
              {group.items.map((action) => {
                optionIndex += 1;
                const index = optionIndex;
                const Icon = action.icon;
                return (
                  <button
                    key={action.id}
                    id={`${listboxId}-option-${action.id}`}
                    type="button"
                    role="option"
                    aria-selected={index === activeIndex}
                    className="command-option"
                    tabIndex={-1}
                    onMouseMove={() => setActiveIndex(index)}
                    onClick={() => choose(action)}
                  >
                    <span className="command-option-icon" aria-hidden="true">
                      <Icon />
                    </span>
                    <span className="command-option-copy">
                      <span className="command-option-label">{action.label}</span>
                      <span className="command-option-description">{action.description}</span>
                    </span>
                    <span className="command-option-enter" aria-hidden="true">
                      Enter
                    </span>
                  </button>
                );
              })}
            </div>
          ))
        )}
      </div>

      <div className="command-footer">
        <span className="command-hint">
          <span className="command-kbd">↑</span>
          <span className="command-kbd">↓</span>
          Navigate
        </span>
        <span className="command-hint">
          <span className="command-kbd">Enter</span>
          Open
        </span>
        <span className="command-hint">
          <span className="command-kbd">Esc</span>
          Close
        </span>
        <span className="command-footer-note">Pages available to your role</span>
      </div>
    </Dialog>
  );
}
